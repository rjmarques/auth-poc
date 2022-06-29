package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rjmarques/auth-poc/keycloak/auth"
)

type HttpServer struct {
	server *http.Server
}

func NewServer(port string, authProvider *auth.AuthAPI) *HttpServer {
	secureWrapper, loginHandler := auth.NewApiMiddleware(authProvider)

	// all these routes are secure and will be checked for a validated session
	secureMux := mux.NewRouter()
	secureMux.Use(secureWrapper) // auth everything

	// api level handlers
	api := secureMux.PathPrefix("/api").Subrouter()
	api.HandleFunc("/data", protectedData)

	// this router will aggregate all subrouters, including secure and public routes
	r := mux.NewRouter()
	r.PathPrefix("/api").Handler(secureMux)
	r.HandleFunc("/login", loginHandler).Methods("POST")

	// create a server object
	s := &HttpServer{
		server: &http.Server{
			Addr:    fmt.Sprintf(":%s", port),
			Handler: r,
		},
	}

	return s
}

func (s *HttpServer) Listen() error {
	return s.server.ListenAndServe()
}

type ProtectedData struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
}

func protectedData(w http.ResponseWriter, r *http.Request) {
	var pd ProtectedData

	user, ok := r.Context().Value(auth.UserKey).(string)
	if !ok {
		http.Error(w, "invalid session, no username", http.StatusInternalServerError)
		return
	}
	pd.Username = user

	roles, _ := r.Context().Value(auth.RolesKey).([]string)
	fmt.Println(roles)
	pd.Roles = roles

	data, err := json.Marshal(&pd)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
