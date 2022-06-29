package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

func NewApiMiddleware(api *AuthAPI) (authingWrapper func(handler http.Handler) http.Handler, loginHandler http.HandlerFunc) {
	// Create the keyfunc options. Refresh the JWKS every hour and log errors.
	refreshInterval := time.Hour
	options := keyfunc.Options{
		RefreshInterval: refreshInterval,
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.KeyFunc\nError: %s", err.Error())
		},
	}

	// Create the JWKS from the resource at the given URL.
	jwks, err := keyfunc.Get(api.certsURL, options)
	if err != nil {
		panic(fmt.Sprintf("Failed to create JWKS from resource at the given URL.\nError: %s", err.Error()))
	}

	m := &apiMiddleware{api, jwks}

	authingWrapper = m.passiveAuthingHandler
	loginHandler = m.login

	return
}

type apiMiddleware struct {
	api  *AuthAPI
	jwks *keyfunc.JWKS
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expiresIn"` // seconds
}

func (m *apiMiddleware) login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "invalid username or password", http.StatusBadRequest)
		return
	}

	jwt, err := m.api.gocloak.Login(context.Background(), m.api.clientId, m.api.clientSecret, m.api.realm, req.Username, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var res = LoginResponse{Token: jwt.AccessToken, ExpiresIn: jwt.ExpiresIn}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(&res)
	if err != nil {
		http.Error(w, fmt.Sprintf("error creating response: %s", err), http.StatusInternalServerError)
	}
}

func (m *apiMiddleware) passiveAuthingHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// try to extract Authorization parameter from the HTTP header
		authorization := r.Header.Get("Authorization")

		if authorization == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		// extract Bearer token
		token := extractToken(authorization)

		if token == "" {
			http.Error(w, "Bearer Token missing", http.StatusUnauthorized)
			return
		}

		// parse the JWT.
		jwt, err := jwt.Parse(token, m.jwks.Keyfunc)
		if err != nil {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		// check if the token is valid.
		if !jwt.Valid {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}
		log.Println("The token is valid.")

		// decode the toke to get user related data
		_, claims, err := m.api.gocloak.DecodeAccessToken(context.Background(), token, m.api.realm)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid or malformed token: %s", err.Error()), http.StatusUnauthorized)
			return
		}

		// check if user has required role
		if !hasRole(*claims, "api") {
			http.Error(w, "not allowed", http.StatusUnauthorized)
			return
		}

		r = r.WithContext(setJWTClaims(r.Context(), *claims))
		h.ServeHTTP(w, r)
	})
}

func extractToken(authorization string) string {
	return strings.Replace(authorization, "Bearer ", "", 1)
}
