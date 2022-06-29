package auth

import (
	"fmt"

	"github.com/Nerzal/gocloak/v11"
)

type AuthAPI struct {
	gocloak      gocloak.GoCloak // keycloak client
	clientId     string          // clientId specified in Keycloak
	clientSecret string          // client secret specified in Keycloak
	realm        string          // realm specified in Keycloak
	certsURL     string          //openid-connect
}

func NewAuth(keycloakURL, clientID, clientSecret, realm string) *AuthAPI {
	return &AuthAPI{
		// need to override some default URLs. See: https://github.com/Nerzal/gocloak/issues/346
		gocloak:      gocloak.NewClient(keycloakURL, gocloak.SetAuthAdminRealms("admin/realms"), gocloak.SetAuthRealms("realms")),
		clientId:     clientID,
		clientSecret: clientSecret,
		realm:        realm,
		certsURL:     fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", keycloakURL, realm),
	}
}
