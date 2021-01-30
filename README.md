# OIDC Redirect

OIDC Redirect is a small Node server that allows [OHIF](https://ohif.org), or other OIDC enabled web apps, running on a host that has already been authenticated by some other means (ie. local login, VM displayed to only to an authenticated user, etc.) to immediately connect to a Google Cloud Healthcare PACS. OIDC Redirect will use environment variables to determine the logged-in user.

The server is meant to be run and bound to the loopback address (127.0.0.1) of authenticated host. The server will blindly return tokens to any callers.

The server could be made accessible only to a specific subnet in order to allow access for all users on that subnet – although some additional hardening would be appropriate. Please contact me at [spalte@naturalimage.ch](mailto:spalte@naturalimage.ch) if you are interested in this use case.

Authentication with Google can be accomplished by either passing an OAuth2 refresh_token alongside with the client_id and client_secret, or can be set up by directly using a Service Account using a Google credential file in JSON format.

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

OHIF will open, initiate an OIDC session with the OIDC Redirect, and connect to the open `server.dcmjs.org` DICOMweb server as directed in the app-config.js configuration file. If you inspect the network connection though, you will note that an `Authorization` HTTP header has been added (default "super_token"). In order to point to a Google Cloud Healthcare PACS, modify WADO-RS URIs in the app-config.js file that is passed to OHIF.

---

## Environment variables

`LOGGED_IN_USER_SUB` must be defined.

`LOGGED_IN_USER_NAME` will be returned by the userinfo endpoint if defined.

`LOGGED_IN_USER_EMAIL` will be returned by the userinfo endpoint if defined.

`ISSUER` can be set to specify at what URL the service will be running (ex. `http://127.0.0.1:8085`). By default an attempt will be make to derive it from the request.

If `GOOGLE_SERVICE_ACCOUNT_CREDENTIAL_FILE` is defined, an Access Token acquired from Google for that service account will be returned. This variable should point to a Google Service account credential file in JSON format.

Alternatively, `GOOGLE_REFRESH_TOKEN_FILE`, `GOOGLE_CLIENT_ID`, and `GOOGLE_CLIENT_SECRET_FILE` can be be specified in which case Access Tokens are obtained by using the refresh token.

`LISTEN_PORT` can be used to set what port will be used. Default is 80.
