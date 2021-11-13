'''
Example on how to retrieve a jwt from machine to machine point of view.
Your application should be registered on the oauthsrv server in order to work.
In the registration process you should receive a `client_id` and a `client_secret`.

NOTE: this feature is not implemented in `oauthsrv`
'''
import requests

client_id = '<MY-CLIENT-ID>'
client_secret = '<MY-CLIENT-PASSWORD>'


def main():
    resp = requests.post('http://localhost:8080/oauth/v2/auth?grant_type=client_credentials', data={
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': '*' # retrieve all the scopes
    })

    assert resp.status_code == 200, f'{resp.status_code} != 200'
    assert 'access_token' in resp.json()


if __name__ == '__main__':
   main()
