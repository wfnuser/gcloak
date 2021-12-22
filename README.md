# Gcloak
The gin middleware implementation for Keycloak.

# Prerequisite
* keycloak should provide service

# How to use?

## Token Exchange
In `gcloak/service`, we provide a gin token handler. You can get token by send `GET` request with parameter `code` in URL. If the code you send is valid, IDToken and AccessToken will be set in cookies with key `${IDTokenCookieName}` and `${AccessTokenCookieName}` which are two parameters you should send to the token handler function.

## Auth Middleware
In `gcloak/gcloak`, we provide an auth middleware. You can easily integrate it with your gin application by adding the following code.
```go
a := v1.Group("")
a.Use(gcloak.KeyCloakAuth(conf, accessMap))
```
You should provide following fields in gcloak configuration.
`RedirectURL` is the redirect url you allowed to jumpback.
`Endpoint` is the keycloak service endpoint.
`ClientID` is the client id you config in Keycloak.
`ClientSecret` is the client secret key you config in Keycloak.
`TTL` is the token's time to live.
`IDTokenCookieName` and `AccessTokenCookieName` are the keys of cookies you set idtoken and accesstoken.

You should also provide a mapping from `url` to `roles`. Following is a sample:
```	go
    var accessMap map[string][]string = map[string][]string{
		"/v1/ping": {"dev"},
	}
```


If gin request's cookies don't contain a valid idtoken and accesstoken, the middleware will return 401 or 403.


# Sample code
you should create realm with name `cloud`

```go
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

```