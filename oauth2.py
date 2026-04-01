import jwt
import httpx

import time, math, json

class OAuth2():
    def __init__(self, credentials_location):
        self.base_url = "https://api.ibkr.com"

        with open(credentials_location) as file:
            self.credentials = json.load(file)

        with open(self.credentials["private_key_location"]) as file:
            self.pkey = file.read()

        self.signing_headers = {
            "alg": "RS256",
            "typ": "JWT",
            "kid": self.credentials["client_key_id"]
        }

    def authenticate(self):
        # 1. Retrieve Access Token
        access_token_response = self.get_access_token()
        self.handle_response(access_token_response)
        access_token = access_token_response.json()["access_token"]

        # 2. Create SSO Session
        bearer_token_response = self.create_sso_session(access_token)
        self.handle_response(bearer_token_response)
        self.bearer_token = bearer_token_response.json()["access_token"]
        self.bearer_header = {"Authorization": "Bearer " + self.bearer_token}

        # 3. Validate SSO Session
        validate_response = self.validate_sso()
        self.handle_response(validate_response)

        # 4. Initialise Brokerage Session
        init_session_response = self.init_brokerage_session()
        self.handle_response(init_session_response)
        if init_session_response.json()["authenticated"]:
            print("Authenticated")
        else:
            print("Failure to initialise brokerage session")

    def print_response(self, response):
        print(f"Status code: {response.status_code}")
        print(f"Request URL: {response.url}")
        print(f"Request Headers: {response.request.headers}")
        print(f"Response Body:\n {json.dumps(response.json(), indent=2)}\n")

    def handle_response(self, response):
        self.print_response(response)
        if response.status_code > 200: exit(1)

    def get_access_token(self):
        
        now = math.floor(time.time())

        token_claims = {
            "iss": self.credentials["client_id"],
            "sub": self.credentials["client_id"],
            "aud": "/token",
            "exp": now + 20,
            "iat": now - 10
        }

        jws = jwt.encode(payload=token_claims, headers=self.signing_headers, key=self.pkey)

        form_data = {
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": jws,
            "grant_type": "client_credentials",
            "scope": self.credentials["scope"]
        }

        response = httpx.post(f"{self.base_url}/oauth2/api/v1/token", data=form_data)

        return response

    def create_sso_session(self, access_token):

        now = math.floor(time.time())

        headers = {"Authorization": "Bearer " + access_token}

        sso_claims = {
            "ip": self.credentials["ip"],
            "alternativeIps": self.credentials["alternative_ips"],
            "credential": self.credentials["credential"],
            "iss": self.credentials["client_id"],
            "exp": now + 86400,
            "iat": now
            }

        jws = jwt.encode(payload=sso_claims, headers=self.signing_headers, key=self.pkey)

        response = httpx.post(f"{self.base_url}/gw/api/v1/sso-sessions", headers=headers, data=jws)

        return response
    
    def validate_sso(self):
        url = f"{self.base_url}/v1/api/sso/validate"
        response = httpx.get(url, headers=self.bearer_header)

        return response
    
    def init_brokerage_session(self):
        url = f"{self.base_url}/v1/api/iserver/auth/ssodh/init"
        data = {"publish": True, "compete": True}

        response = httpx.post(url, json=data, headers=self.bearer_header)

        return response