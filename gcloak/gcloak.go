package gcloak

import (
	"context"
	"net/http"

	oidc "github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
)

type GCloakConf struct {
	URL                   string
	Realm                 string
	Endpoint              string
	RedirectURL           string
	ClientID              string
	ClientSecret          string
	IDTokenCookieName     string
	AccessTokenCookieName string
	TTL                   int64
}

func KeyCloakAuth(conf GCloakConf, accessMap map[string][]string) gin.HandlerFunc {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, conf.Endpoint)
	oidcConfig := &oidc.Config{
		ClientID: conf.ClientID,
	}
	verifier := provider.Verifier(oidcConfig)
	return func(ctx *gin.Context) {
		// TODO: Authorize timeout mechanism
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

		// IDToken missing is not allowed
		if rawIDToken == "" {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		_, err = verifier.Verify(ctx, rawIDToken)
		if err != nil {
			// TODO: fine-grained verification error should be exposed
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		t, e := decodeKeyCloakToken(rawAccessToken)
		if e != nil {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if accessMap != nil && accessMap[ctx.Request.URL.Path] != nil {
			authorized := false
			for _, role := range t.RealmAccess.Roles {
				for _, granted := range accessMap[ctx.Request.URL.Path] {
					if granted == role {
						authorized = true
						break
					}
				}
				if authorized {
					break
				}
			}
			if !authorized {
				ctx.AbortWithStatus(http.StatusForbidden)
			}
		}

		ctx.Next()
	}
}
