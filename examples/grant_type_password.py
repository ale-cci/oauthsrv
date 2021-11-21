import requests

YOUR_USERNAME = 'test@email.com'
YOUR_PASSWORD = 'root'

response = requests.post(
    'http://localhost:8080/oauth/v2/auth',
    params={
        'grant_type': 'password',
    },
    data={
        'username': YOUR_USERNAME,
        'password': YOUR_PASSWORD,
    }
)

assert response.status_code == 200

json_data = response.json()
assert 'access_token' in json_data
print(f'Obtained access token: {json_data["access_token"]}')
