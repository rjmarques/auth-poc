package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const CookieAccessToken = "accesstkn"
const CookieRefreshToken = "refreshtkn"

func NewWebMiddleware(api *AuthAPI) (authingWrapper func(handler http.Handler) http.Handler, loginHandler http.HandlerFunc, logoutHandler http.HandlerFunc) {
	m := &webMiddleware{api}

	authingWrapper = m.activeAuthingHandler
	loginHandler = m.formLogin
	logoutHandler = m.logout

	return
}

type webMiddleware struct {
	api *AuthAPI
}

func (m *webMiddleware) formLogin(w http.ResponseWriter, r *http.Request) {
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

	// set both cookies
	http.SetCookie(w, &http.Cookie{
		Name:     CookieAccessToken,
		HttpOnly: true,
		Secure:   true,
		Value:    jwt.AccessToken,
		Expires:  time.Now().Add(time.Duration(jwt.ExpiresIn) * time.Second),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     CookieRefreshToken,
		HttpOnly: true,
		Secure:   true,
		Value:    jwt.RefreshToken,
		Expires:  time.Now().Add(time.Duration(jwt.RefreshExpiresIn) * time.Second),
	})

	w.WriteHeader(http.StatusOK)
}

func (m *webMiddleware) logout(w http.ResponseWriter, r *http.Request) {
	var token string

	cs := r.Cookies()
	for _, c := range cs {
		if c.Name == CookieRefreshToken {
			token = c.Value
			break
		}
	}

	if token != "" {
		// revoke session in keycloak
		err := m.api.gocloak.Logout(context.Background(), m.api.clientId, m.api.clientSecret, m.api.realm, token)
		if err != nil {
			fmt.Printf("unable to log user out: %s\n", err.Error())
		}
	}

	// clear cookies
	http.SetCookie(w, &http.Cookie{
		Name:     CookieAccessToken,
		HttpOnly: true,
		Secure:   true,
		Value:    "",
		Expires:  time.Unix(0, 0),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     CookieRefreshToken,
		HttpOnly: true,
		Secure:   true,
		Value:    "",
		Expires:  time.Unix(0, 0),
	})

	w.WriteHeader(http.StatusOK)
}

func (m *webMiddleware) activeAuthingHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string

		cs := r.Cookies()
		for _, c := range cs {
			if c.Name == CookieAccessToken {
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
		_, claims, err := m.decodeToken(token)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid or malformed token: %s", err.Error()), http.StatusUnauthorized)
			return
		}

		r = r.WithContext(setJWTClaims(r.Context(), *claims))
		h.ServeHTTP(w, r)
	})
}

func (m *webMiddleware) decodeToken(token string) (*jwt.Token, *jwt.MapClaims, error) {
	return m.api.gocloak.DecodeAccessToken(context.Background(), token, m.api.realm)
}
