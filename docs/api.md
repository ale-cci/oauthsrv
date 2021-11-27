> The application is still under development.
> This APIs could be subject to change on the definitive version of this project.
### Authentication
```http
POST /oauth/v2/auth?grant_type=password HTTP/1.1
Content-Type: application/json

{
    "username": "test@email.com",
    "password": "root",
}
```

```http
HTTP/1.1 200 OK
{
    "id_token": "",
    "access_token": "",
    "refresh_token": "",
}
```

### Users:
##### Create a new user
```http
POST /api/v1/users HTTP/1.1
Content-Type: application/json
Authorization: Bearer <xxx>

{
    "email": "",
    "email_verified": "boolean (optional)",
}
```

##### Add group to an existing user
This request could only be performed by users in `admin` or `manager` group,
or if `project-id` is specified in the group name, by users with group: `<project-id>:admin`
and `<project-id>:manager` groups.

```http
POST /app/v1/users/:user-id/groups HTTP/1.1
Content-Type: application/json
Authorization: Bearer <xxx>

{
    "group": "<project-id>:<group>"
}
```

##### Delete group of an existing user
This endpoint has the same restrictions of add group, but `manager` could not delete
`admin` group, and `<project-id>:manager` could not delete `<project-id>:admin` group.
Otherwise `403`.

```http
DELETE /app/v1/users/:user-id/groups/:group HTTP/1.1
Content-Type: application/json
Authorization: Bearer <xxx>
```


---
### Projects:
##### Create a project
```http
POST /api/v1/project/ HTTP/1.1
Content-Type: application/json
Authorization: Bearer <xxx>

{
    "color": "#000000 (optional)",
    "name": "required",
    "description": "(optional)",
    "terms_conditions": "(optional)",
}
```
Users that perform this call should be in one of the following groups (403 otherwise):
- `admin`
- `manager`

When the endpoint is called, the group `<project-id>:admin` is automatically
assigned at the authenticated user.

On the `projects` document, an entry like this is added:

```json
{
    "id": "<random-uuid>",
    "color": "#000000",
    "name": "",
    "description": "",
    "terms_conditions": "https://url.for.terms.and.conditions",
}
```

###### On success:
```http
HTTP/1.1 201 Created
Content-Type: application/json; charset=utf-8

{ "data": { "id": "<project-id>" } }
```

---

### Credentials:
##### Create project's credentials
In order to obtain an access token, with a specific grant type, a project
needs a credential record.
A `credential` could be:
- `public` to allow grant types: `implicit`, `pkce`
- `confidential` to allow grant types: `code`, `password`, `client_credentials`


```http
POST /api/v1/project/:proj-id/credentials HTTP/1.1
Content-Type: application/json
Authorization: Bearer <xxx>

{
    "type": "public or private",
    "description": "",
    "redirect_uris": []
}
```
Users that perform this call should be in one of the following groups (403 otherwise):
- `admin`
- `manager`
- `<proj-id>:admin`
- `<proj-id>:manager`

When the endpoint is called, a record in `credentials` document is added, like
the following:
```json
{
    "project_id": "<proj-id>",
    "type": "public",
    "description": "example",
    "client_id": "...",
    "client_password": "...",
    "redirect_uris": [
        "http://example.com",
    ]
}
```
When a user in the `manager` or `admin` groups calls the endpoint,

the app-id is automatically generated, and the user is added to the `app-id:admin` group.


### Scope:
##### Create a scope
Scopes could only be created by users in group:
- `admin`
- `manager`
- `<proj-id>:admin`
- `<proj-id>:manager`

```
POST /api/v1/project/:proj-id/scopes HTTP/1.1
Content-Type: application/json
Authorization: Bearer <xxx>

{
    "pattern": "<proj-id>/...",
    "groups": ["optional"],
    "grant": {"any json object": []}
}
```
