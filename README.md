# Web API

## OAuth 2.0 Client

### Requirements

```
pip install pyjwt[crypto] httpx
```

### Usage

```
from oauth2 import OAuth2

oa = OAuth2(credentials_location={PATH_TO_CREDENTIALS_FILE})
oa.authenticate()
```