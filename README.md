## OAuthSrv
>
### Usage
Default credentials
```text
Username: test@email.com
Password: root
```

### Contributing
```sh
$ git config core.hooksPath 'git-hooks'
```

### Run Test suite
```sh
$ docker-compose run --rm oauthsrv go test ./...
```

### MongoDB schema:
```
oidc
 - identities: list of registered users
 - apps: registered applications (with client secret + client id)
```
