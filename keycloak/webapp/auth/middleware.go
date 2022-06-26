package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const CookieKey = "token"

func NewMiddleware(api *AuthAPI) (authingWrapper func(handler http.Handler) http.Handler, loginHandler http.HandlerFunc) {
	m := &middleware{api}

	authingWrapper = m.authingHandler
	loginHandler = m.login

	return
}

type middleware struct {
	api *AuthAPI
}

func (m *middleware) login(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "error parsing form", http.StatusBadRequest)
		return
	}

	form := r.PostForm
	username := form.Get("username")
	password := form.Get("password")
	if username == "" || password == "" {
		http.Error(w, "invalid username or password", http.StatusBadRequest)
		return
	}

	jwt, err := m.api.gocloak.Login(context.Background(), m.api.clientId, m.api.clientSecret, m.api.realm, username, password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	cookie := &http.Cookie{
		Name:     CookieKey,
		HttpOnly: true,
		Secure:   true,
		Value:    jwt.AccessToken,
		Expires:  time.Now().Add(time.Duration(jwt.ExpiresIn) * time.Second),
	}

	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusOK)
}

type ContextKey string

const (
	UserKey  ContextKey = "user"
	RolesKey ContextKey = "roles"
)

func (m *middleware) authingHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string

		cs := r.Cookies()
		for _, c := range cs {
			if c.Name == CookieKey {
				token = c.Value
				break
			}
		}

		if token == "" {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		// call Keycloak API to verify the access token
		result, err := m.api.gocloak.RetrospectToken(context.Background(), token, m.api.clientId, m.api.clientSecret, m.api.realm)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid or expired token: %s", err.Error()), http.StatusUnauthorized)
			return
		}

		// check if the token isn't expired
		if !*result.Active {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		// decode the toke to get user related data
		_, claims, err := m.api.gocloak.DecodeAccessToken(context.Background(), token, m.api.realm)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid or malformed token: %s", err.Error()), http.StatusUnauthorized)
			return
		}

		r = r.WithContext(setJWTClaims(r.Context(), *claims))
		h.ServeHTTP(w, r)
	})
}

func setJWTClaims(ctx context.Context, claims jwt.MapClaims) context.Context {
	ctx = context.WithValue(ctx, UserKey, claims["preferred_username"])

	// there's probably an easier way with via some JSON parsing, but can't be bothered...
	access, _ := claims["realm_access"].(map[string]interface{})
	rawRoles, _ := access["roles"].([]interface{})
	var roles []string
	for _, r := range rawRoles {
		roles = append(roles, fmt.Sprintf("%v", r))
	}

	return context.WithValue(ctx, RolesKey, roles)
}
