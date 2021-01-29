# OIDC Redirect

## Running with Docker-Compose

Run:

```shell
docker-compose up --build
```

This will build the OIDC redirect image, and launch it (port 8085) along with OHIF (port 3000).

Once launched you should be able to open OHIF locally.

```url
http://127.0.0.1:3000
```

OHIF will open, initial an OIDC session with the OIDC Redirector, and connect to the open `server.dcmjs.org` DICOMweb server as directed in the app-config.js configuration file. If you inspect the network connection though, you will note that an `Authorization` HTTP header has been added (default "supertoken").

---

## Environment variables

`LOGGED_IN_USER_SUB` must be defined.

`LOGGED_IN_USER_NAME` will be returned by the userinfo endpoint if defined.

`LOGGED_IN_USER_EMAIL` will be returned by the userinfo endpoint if defined.

`ISSUER` can be set to specify at what URL the service will be running (ex. `http://127.0.0.1:8085`). By default it will attempt to derive it from the request.

If `SERVICE_ACCOUNT_PRIVATE_KEY_FILE` and `SERVICE_ACCOUNT_EMAIL` are defined, this provider will return an Access Token acquired from Google for that service account.

Alternatively, `GOOGLE_REFRESH_TOKEN_FILE`, `GOOGLE_CLIENT_ID`, and `GOOGLE_CLIENT_SECRET_FILE` can be be specified in which case Access Tokens are obtained by using the refresh token.

`LISTEN_PORT` can be used to set what port will be used. Default 80.
