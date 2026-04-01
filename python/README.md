# Web API OAuth 2.0 Client

### Requirements

```
pip install pyjwt[crypto] httpx
```

### Usage

Import the OAuth2 class as required. To instantiate and authenticate:

```
oa = OAuth2(credentials_location={PATH_TO_CREDENTIALS_FILE})
oa.authenticate()
```