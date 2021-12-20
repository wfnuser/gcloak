package gcloak

import (
	"fmt"
	"net/http"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
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

func decodeToken(tokenString string) (map[string]interface{}, error) {
	var claims map[string]interface{} // generic map to store parsed token
	// decode JWT token without verifying the signature
	token, _ := jwt.ParseSigned(tokenString)
	err := token.UnsafeClaimsWithoutVerification(&claims)
	return claims, err
}

func TokenHandler(ctx *gin.Context) {
	fmt.Println("")
	provider, err := oidc.NewProvider(ctx, conf.Endpoint)
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)
	}
	oidcConfig := &oidc.Config{
		ClientID: conf.ClientID,
	}
	verifier := provider.Verifier(oidcConfig)
	oauth2Config := oauth2.Config{
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		// 天坑；这个必须得写对...
		RedirectURL: "http://localhost:8181/v1/token",
		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email", "roles"},
	}
	oauth2Token, err := oauth2Config.Exchange(ctx, ctx.Request.URL.Query().Get("code"))
	if err != nil {
		fmt.Println("Failed to exchange token: " + err.Error())
		ctx.AbortWithStatus(http.StatusForbidden)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		ctx.AbortWithStatus(http.StatusForbidden)
		return
	}
	rawAccessToken, ok := oauth2Token.Extra("access_token").(string)
	if !ok {
		ctx.AbortWithStatus(http.StatusForbidden)
		return
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		ctx.AbortWithStatus(http.StatusForbidden)
		return
	}
	addCookie(ctx.Writer, conf.IDTokenCookieName, rawIDToken, time.Duration(conf.TTL)*time.Minute)
	addCookie(ctx.Writer, conf.AccessTokenCookieName, rawAccessToken, time.Duration(conf.TTL)*time.Minute)

	var IDTokenClaims interface{}
	if err := idToken.Claims(&IDTokenClaims); err != nil {
		ctx.AbortWithStatus(http.StatusForbidden)
		return
	}

	ctx.JSON(200, IDTokenClaims)
}
