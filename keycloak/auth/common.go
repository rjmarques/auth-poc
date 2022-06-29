package auth

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

type ContextKey string

const (
	UserKey  ContextKey = "user"
	RolesKey ContextKey = "roles"
)

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

func hasRole(claims jwt.MapClaims, wantedRole string) bool {
	access, _ := claims["realm_access"].(map[string]interface{})
	rawRoles, _ := access["roles"].([]interface{})
	for _, r := range rawRoles {
		role := fmt.Sprintf("%v", r)
		if role == wantedRole {
			return true
		}
	}
	return false
}
