package gcloak

import (
	"gopkg.in/square/go-jose.v2/jwt"
)

type ServiceRole struct {
	Roles []string `json:"roles"`
}

type KeyCloakToken struct {
	Jti               string                 `json:"jti,omitempty"`
	Exp               int64                  `json:"exp"`
	Nbf               int64                  `json:"nbf"`
	Iat               int64                  `json:"iat"`
	Iss               string                 `json:"iss"`
	Sub               string                 `json:"sub"`
	Typ               string                 `json:"typ"`
	Azp               string                 `json:"azp,omitempty"`
	Nonce             string                 `json:"nonce,omitempty"`
	AuthTime          int64                  `json:"auth_time,omitempty"`
	SessionState      string                 `json:"session_state,omitempty"`
	Acr               string                 `json:"acr,omitempty"`
	ClientSession     string                 `json:"client_session,omitempty"`
	AllowedOrigins    []string               `json:"allowed-origins,omitempty"`
	ResourceAccess    map[string]ServiceRole `json:"resource_access,omitempty"`
	Name              string                 `json:"name"`
	PreferredUsername string                 `json:"preferred_username"`
	GivenName         string                 `json:"given_name,omitempty"`
	FamilyName        string                 `json:"family_name,omitempty"`
	Email             string                 `json:"email,omitempty"`
	RealmAccess       ServiceRole            `json:"realm_access,omitempty"`
}

func decodeKeyCloakToken(tokenString string) (KeyCloakToken, error) {
	var claims KeyCloakToken // generic map to store parsed token
	token, _ := jwt.ParseSigned(tokenString)
	err := token.UnsafeClaimsWithoutVerification(&claims)
	return claims, err
}
