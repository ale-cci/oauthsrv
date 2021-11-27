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
HTTP/1.1 200 Ok
{
    "id_token": "",
    "access_token": "",
    "refresh_token": "',
}
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
    "type": "public"|"private",
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

