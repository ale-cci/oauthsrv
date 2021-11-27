## OAuthSrv
> Note: this is a project still under development

### Usage:
Default credentials
```text
Username: test@email.com
Password: root
```

###### Application endpoints:
| endpoint| description |
|---------|-------------|
| `/login` | login for not authenticated users ([handle\_login.go](./pkg/handlers/handle_login.go))|
| `/oauth/v2/auth` | asks user to grant authorization, on completions redirects to `redirect_uri` ([handle\_authorize.go](./pkg/handlers/handle_authorize.go))|

For API references go [here](./docs/api.md)

### Contributing
```sh
$ git config core.hooksPath 'git-hooks'
```

### Run Test suite
```sh
$ docker-compose run --rm oauthsrv go test ./...
```
Tests are run inside an isolated docker container, when launched, it automatically
boots up the MongoDB and changes the default database to `test-oidc`

### MongoDB schema:
See [here](./docs/schema.md)
