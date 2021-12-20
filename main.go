package main

import (
	"context"
	"net/http"

	"basic/gcloak"

	oidc "github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

func setupRouter() *gin.Engine {
	// 初始化 Gin 框架默认实例，该实例包含了路由、中间件以及配置信息
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

	v1 := r.Group("v1")
	{
		// routes with authorization
		a := v1.Group("")
		a.Use(gcloak.KeyCloakAuth())
		a.Use(gcloak.KeyCloakAuth())
		// ping for testing
		a.GET("/ping", func(c *gin.Context) {
			c.String(http.StatusOK, "pong")
		})
	}

	v1.GET("/token", gcloak.TokenHandler)
	v1.GET("/login", func(c *gin.Context) {
		c.Redirect(http.StatusFound, oauth2Config.AuthCodeURL("state"))
	})
	return r
}

func main() {
	// 设置路由信息
	r := setupRouter()
	// 启动服务器并监听 8080 端口
	r.Run(":8181")
}
