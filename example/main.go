package main

import (
	"context"
	"net/http"

	"github.com/wfnuser/gcloak"

	oidc "github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

func setupRouter() *gin.Engine {
	// Initialize the gin entity
	r := gin.Default()

	configURL := "http://localhost:8080/auth/realms/cloud"
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, configURL)
	if err != nil {
		panic(err)
	}
	clientID := "myclient"
	clientSecret := "FZu9jL7sG7A1lYvjTO9D7RzXkbNBAGa4"
	redirectURL := "http://localhost:8181/v1/token"
	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "roles"},
	}

	conf := gcloak.GCloakConf{
		Endpoint:              "http://localhost:8080/auth/realms/cloud",
		RedirectURL:           "http://localhost:8181/v1/token",
		IDTokenCookieName:     "KeyCloakCloudID",
		AccessTokenCookieName: "KeyCloakCloudAccess",
		ClientID:              "myclient",
		ClientSecret:          "FZu9jL7sG7A1lYvjTO9D7RzXkbNBAGa4",
		TTL:                   120,
	}

	var accessMap map[string][]string = map[string][]string{
		"/v1/ping": {"dev"},
	}

	v1 := r.Group("v1")
	{
		// routes with authorization
		a := v1.Group("")
		a.Use(gcloak.KeyCloakAuth(conf, accessMap))
		a.Use(gcloak.KeyCloakAuth(conf, accessMap))
		// ping for testing
		a.GET("/ping", func(c *gin.Context) {
			c.String(http.StatusOK, "pong")
		})
	}

	v1.GET("/token", gcloak.TokenHandler(conf))
	v1.GET("/login", func(c *gin.Context) {
		c.Redirect(http.StatusFound, oauth2Config.AuthCodeURL("state"))
	})
	return r
}

func main() {
	r := setupRouter()
	r.Run(":8181")
}
