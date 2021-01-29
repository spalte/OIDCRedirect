const fs = require('fs');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const http = require('http');
const url = require('url');

const requestListener = function (request, response) {
    const url = new URL(request.url, `http://${request.headers.host}`);

    switch (url.pathname) {
      case '/.well-known/openid-configuration':
        return configurationListener(request, response);
      default:
        response.writeHead(404, {'Content-Type': 'text/plain'});
        response.write('404 Not Found\n');
        response.end();
        return;
    }
}

const configurationListener = function (request, response) {
    const url = new URL(request.url, `http://${request.headers.host}`);

    const configuration = {
        issuer: `${url.origin}`,
        authorization_endpoint: `${url.origin}/auth`,
        token_endpoint: `${url.origin}/token`,
        userinfo_endpoint: `${url.origin}/userinfo`,
        response_types_supported: [
         'code',
         'token',
         'id_token',
         'code token',
         'code id_token',
         'token id_token',
         'code token id_token',
         'none',
        ],
        subject_types_supported: [
         'public',
        ],
        id_token_signing_alg_values_supported: [
         'RS256',
        ],
        scopes_supported: [
         'openid',
         'email',
         'profile',
        ],
        'token_endpoint_auth_methods_supported': [
         'client_secret_post',
         'client_secret_basic',
        ],
        claims_supported: [
         'aud',
         'email',
         'email_verified',
         'exp',
         'family_name',
         'given_name',
         'iat',
         'iss',
         'locale',
         'name',
         'picture',
         'sub',
        ],
        code_challenge_methods_supported: [
         'plain',
         'S256',
        ],
        grant_types_supported: [
         'authorization_code',
         'refresh_token',
         'urn:ietf:params:oauth:grant-type:device_code',
         'urn:ietf:params:oauth:grant-type:jwt-bearer',
        ]
       
    }

    response.writeHead(200, {'Content-Type': 'application/json'});


    response.write(JSON.stringify(configuration, null, 2));
    response.end();
}

const server = http.createServer(requestListener);
server.listen(8085, '0.0.0.0', () => {
    console.log(`Server is running`);
});
