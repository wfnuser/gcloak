package gcloak

import (
	"net/http"

	oidc "github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
)

type GCloakConf struct {
	Endpoint              string
	IDTokenCookieName     string
	AccessTokenCookieName string
	ClientID              string
	ClientSecret          string
	TTL                   int64
}

var conf GCloakConf = GCloakConf{
	Endpoint:              "http://localhost:8080/auth/realms/cloud",
	IDTokenCookieName:     "KeyCloakCloudID",
	AccessTokenCookieName: "KeyCloakCloudAccess",
	ClientID:              "myclient",
	ClientSecret:          "FZu9jL7sG7A1lYvjTO9D7RzXkbNBAGa4",
	TTL:                   120,
}

var accessMap map[string][]string = map[string][]string{
	"/v1/ping": {"dev"},
}

func KeyCloakAuth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var rawIDToken string
		var rawAccessToken string
		for _, cookie := range ctx.Request.Cookies() {
			if cookie.Name == conf.IDTokenCookieName {
				rawIDToken = cookie.Value
			}
			if cookie.Name == conf.AccessTokenCookieName {
				rawAccessToken = cookie.Value
			}
		}
		if rawIDToken == "" {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
		provider, err := oidc.NewProvider(ctx, conf.Endpoint)
		oidcConfig := &oidc.Config{
			ClientID: conf.ClientID,
		}
		verifier := provider.Verifier(oidcConfig)
		_, err = verifier.Verify(ctx, rawIDToken)
		if err != nil {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}

		m, e := decodeToken(rawAccessToken)
		if e != nil {
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		// fmt.Println(ctx.Request.URL.Path)
		// fmt.Println(m["realm_access"].(map[string](interface{}))["roles"].([]interface{}))
		if accessMap[ctx.Request.URL.Path] != nil {
			valid := false
			for _, role := range m["realm_access"].(map[string](interface{}))["roles"].([]interface{}) {
				for _, grant := range accessMap[ctx.Request.URL.Path] {
					if grant == role.(string) {
						valid = true
					}
				}
				if valid {
					break
				}
			}
			if !valid {
				ctx.AbortWithStatus(http.StatusForbidden)
			}
		}

		ctx.Next()
	}
}
