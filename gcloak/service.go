package gcloak

import (
	"context"
	"fmt"
	"net/http"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

func TokenHandler(conf GCloakConf) gin.HandlerFunc {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, conf.Endpoint)
	if err != nil {
		panic(err)
	}
	oidcConfig := &oidc.Config{
		ClientID: conf.ClientID,
	}
	verifier := provider.Verifier(oidcConfig)
	oauth2Config := oauth2.Config{
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		RedirectURL:  conf.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "roles"},
	}

	return func(ctx *gin.Context) {
		oauth2Token, err := oauth2Config.Exchange(ctx, ctx.Request.URL.Query().Get("code"))
		if err != nil {
			fmt.Println("Failed to exchange token: " + err.Error())
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		rawAccessToken, ok := oauth2Token.Extra("access_token").(string)
		if !ok {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}

		// TODO: the TTL actually not really work; client can update the ttl easily
		addCookie(ctx.Writer, conf.IDTokenCookieName, rawIDToken, time.Duration(conf.TTL)*time.Minute)
		addCookie(ctx.Writer, conf.AccessTokenCookieName, rawAccessToken, time.Duration(conf.TTL)*time.Minute)

		var IDTokenClaims interface{}
		if err := idToken.Claims(&IDTokenClaims); err != nil {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}

		ctx.JSON(200, IDTokenClaims)
	}
}
