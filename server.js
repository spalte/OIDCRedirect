/* eslint-disable no-console */
/* eslint-disable no-use-before-define */
const fs = require('fs');
const querystring = require('querystring');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const http = require('http');
const NodeRSA = require('node-rsa');

const SERVER_PRIVATE_KEY = new NodeRSA().generateKeyPair().exportKey('pkcs1-private-pem');
const { LOGGED_IN_USER_SUB } = process.env;
const { LOGGED_IN_USER_EMAIL } = process.env;
const { LOGGED_IN_USER_NAME } = process.env;

if (!LOGGED_IN_USER_SUB) {
  console.log('env var LOGGED_IN_USER_SUB is not defined and required');
}

let { LISTEN_PORT } = process.env;
if (!LISTEN_PORT) {
  LISTEN_PORT = 80;
}
LISTEN_PORT = Number(LISTEN_PORT);

let SERVICE_ACCOUNT_PRIVATE_KEY;
let SERVICE_ACCOUNT_EMAIL;

if (process.env.SERVICE_ACCOUNT_PRIVATE_KEY_FILE) {
  SERVICE_ACCOUNT_PRIVATE_KEY = fs.readFileSync(process.env.SERVICE_ACCOUNT_PRIVATE_KEY_FILE, 'ascii');
  SERVICE_ACCOUNT_EMAIL = process.env.SERVICE_ACCOUNT_EMAIL;
}

async function accessTokenFetcher() {
  if (SERVICE_ACCOUNT_PRIVATE_KEY) {
    return getServiceAccountAccessToken();
  }
  return 'supertoken';
}

function requestListener(request, response) {
  const url = new URL(request.url, `http://${request.headers.host}`);

  switch (url.pathname) {
    case '/.well-known/openid-configuration':
      configurationListener(request, response);
      break;
    case '/auth':
      authListener(request, response);
      break;
    case '/token':
      tokenListener(request, response);
      break;
    case '/userinfo':
      userinfoListener(request, response);
      break;
    default:
      response.writeHead(404, { 'Content-Type': 'text/plain' });
      response.write('404 Not Found\n');
      response.end();
  }
}

function configurationListener(request, response) {
  const issuer = getIssuer(request);

  const configuration = {
    issuer,
    authorization_endpoint: `${issuer}/auth`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
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
    claims_supported: [
      'aud',
      'email',
      'exp',
      'iat',
      'iss',
      'name',
      'sub',
    ],
    grant_types_supported: [
      'authorization_code',
    ],
  };

  response.writeHead(200, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
  });

  response.write(JSON.stringify(configuration, null, 2));
  response.end();
}

function authListener(request, response) {
  const url = new URL(request.url, `http://${request.headers.host}`);

  const state = url.searchParams.get('state');
  const code = 'code';

  const redirectUri = new URL(url.searchParams.get('redirect_uri'));

  redirectUri.searchParams.append('code', code);
  redirectUri.searchParams.append('state', state);

  response.writeHead(302, {
    Location: redirectUri.toString(),
  });
  response.end();
}

async function tokenListener(request, response) {
  function readPost() {
    return new Promise((resolve, reject) => {
      let body = '';
      request.on('data', (data) => {
        body += data;
      });
      request.on('end', () => {
        resolve(querystring.parse(body));
      });
      request.on('error', (err) => {
        console.log(err);
        reject(err);
      });
    });
  }

  const clientId = (await readPost()).client_id;
  const issuer = getIssuer(request);

  const idClaims = {
    iss: issuer,
    sub: LOGGED_IN_USER_SUB,
    aud: clientId,
  };
  const idToken = jwt.sign(idClaims, SERVER_PRIVATE_KEY, { algorithm: 'RS256', expiresIn: '1h' });

  const responseBody = {
    access_token: await accessTokenFetcher(),
    token_type: 'Bearer',
    expires_in: 3600,
    id_token: idToken,
  };

  response.writeHead(200, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-store',
    Pragma: 'no-cache',
  });
  response.write(JSON.stringify(responseBody, null, 2));
  response.end();
}

function userinfoListener(request, response) {
  const userinfo = {
    sub: LOGGED_IN_USER_SUB,
    ...(LOGGED_IN_USER_EMAIL && { email: LOGGED_IN_USER_EMAIL }),
    ...(LOGGED_IN_USER_NAME && { name: LOGGED_IN_USER_NAME }),
  };

  response.writeHead(200, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
  });
  response.write(JSON.stringify(userinfo, null, 2));
  response.end();
}

async function getServiceAccountAccessToken() {
  const authenticationJWT = jwt.sign({
    scope: 'https://www.googleapis.com/auth/cloud-platform',
  }, SERVICE_ACCOUNT_PRIVATE_KEY, {
    algorithm: 'RS256',
    issuer: SERVICE_ACCOUNT_EMAIL,
    audience: 'https://oauth2.googleapis.com/token',
    expiresIn: '5m',
  });

  const params = new URLSearchParams();
  params.append('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer');
  params.append('assertion', authenticationJWT);

  return (await axios.post('https://oauth2.googleapis.com/token', params)).data.access_token;
}

function getIssuer(request) {
  const url = new URL(request.url, `http://${request.headers.host}`);

  let issuer = process.env.ISSUER;
  if (!issuer) {
    if (request.headers['x-forwarded-host']) {
      issuer = `${request.headers['x-forwarded-proto']}://${request.headers['x-forwarded-host']}`;
    } else {
      issuer = url.origin;
    }
  }
  return issuer;
}

const server = http.createServer(requestListener);
server.listen(LISTEN_PORT, () => {
  console.log('Server is running');
});
