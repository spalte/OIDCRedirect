/* eslint-disable no-console */
/* eslint-disable no-use-before-define */
const fs = require('fs');
const querystring = require('querystring');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const { pem2jwk } = require('pem-jwk');
const http = require('http');
const NodeRSA = require('node-rsa');

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization',
  'Access-Control-Allow-Credentials': 'true',
  'Access-Control-Max-Age': 86400,
};

const SERVER_PRIVATE_KEY = new NodeRSA().generateKeyPair().exportKey('pkcs1-private-pem');
const SERVER_JWK = pem2jwk(SERVER_PRIVATE_KEY);
const SERVER_JWK_KEY_ID = '0';

const { LOGGED_IN_USER_SUB } = process.env;
const { LOGGED_IN_USER_EMAIL } = process.env;
const { LOGGED_IN_USER_NAME } = process.env;

if (!LOGGED_IN_USER_SUB) {
  console.log('env var LOGGED_IN_USER_SUB is required but is not defined');
}

let { LISTEN_PORT } = process.env;
if (!LISTEN_PORT) {
  LISTEN_PORT = 80;
}
LISTEN_PORT = Number(LISTEN_PORT);

let SERVICE_ACCOUNT_PRIVATE_KEY;
let SERVICE_ACCOUNT_EMAIL;

if (process.env.SERVICE_ACCOUNT_PRIVATE_KEY_FILE) {
  SERVICE_ACCOUNT_PRIVATE_KEY = fs.readFileSync(process.env.SERVICE_ACCOUNT_PRIVATE_KEY_FILE, 'ascii').trim();
  SERVICE_ACCOUNT_EMAIL = process.env.SERVICE_ACCOUNT_EMAIL;
}

let GOOGLE_REFRESH_TOKEN;
let GOOGLE_CLIENT_ID;
let GOOGLE_CLIENT_SECRET;

if (process.env.GOOGLE_CLIENT_SECRET_FILE) {
  GOOGLE_REFRESH_TOKEN = fs.readFileSync(process.env.GOOGLE_REFRESH_TOKEN_FILE, 'ascii').trim();
  GOOGLE_CLIENT_SECRET = fs.readFileSync(process.env.GOOGLE_CLIENT_SECRET_FILE, 'ascii').trim();
  GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
}

async function accessTokenFetcher() {
  if (SERVICE_ACCOUNT_PRIVATE_KEY) {
    return getServiceAccountAccessToken();
  }

  if (GOOGLE_REFRESH_TOKEN) {
    return refreshAccessToken();
  }

  return getStaticAccessToken();
}

function requestListener(request, response) {
  (async function selectPath() {
    const url = new URL(request.url, `http://${request.headers.host}`);

    if (request.method === 'OPTIONS') {
      response.writeHead(204, CORS_HEADERS);
      response.end();
      return;
    }

    switch (url.pathname) {
      case '/.well-known/openid-configuration':
        await configurationListener(request, response);
        break;
      case '/auth':
        await authListener(request, response);
        break;
      case '/token':
        await tokenListener(request, response);
        break;
      case '/userinfo':
        await userinfoListener(request, response);
        break;
      case '/certs':
        await certsListener(request, response);
        break;
      default:
        response.writeHead(404, {
          'Content-Type': 'text/plain',
          ...CORS_HEADERS,
        });
        response.write('404 Not Found\n');
        response.end();
    }
  }()).catch((error) => {
    console.log(error);
    response.writeHead(500, {
      'Content-Type': 'text/plain',
      ...CORS_HEADERS,
    });
    response.write('500 Server Error\n');
    response.end();
  });
}

async function configurationListener(request, response) {
  const issuer = getIssuer(request);

  const configuration = {
    issuer,
    authorization_endpoint: `${issuer}/auth`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/certs`,
    response_types_supported: [
      'code',
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
      'refresh_token',
    ],
  };

  response.writeHead(200, {
    'Content-Type': 'application/json',
    ...CORS_HEADERS,
  });

  response.write(JSON.stringify(configuration, null, 2));
  response.end();
}

async function authListener(request, response) {
  const url = new URL(request.url, `http://${request.headers.host}`);

  const state = url.searchParams.get('state');
  const code = 'code';

  const redirectUri = new URL(url.searchParams.get('redirect_uri'));

  redirectUri.searchParams.append('code', code);
  redirectUri.searchParams.append('state', state);

  response.writeHead(302, {
    Location: redirectUri.toString(),
    ...CORS_HEADERS,
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
        reject(err);
      });
    });
  }

  const requestParameters = await readPost();
  const clientId = requestParameters.client_id;
  const issuer = getIssuer(request);

  const idClaims = {
    iss: issuer,
    sub: LOGGED_IN_USER_SUB,
    aud: clientId,
  };

  const accessTokenData = await accessTokenFetcher();

  const responseBody = {
    access_token: accessTokenData.access_token,
    token_type: accessTokenData.token_type,
    expires_in: accessTokenData.expires_in,
    ...(requestParameters.grant_type === 'authorization_code' && {
      refresh_token: 'refresh_me',
      id_token: jwt.sign(idClaims, SERVER_PRIVATE_KEY, { algorithm: 'RS256', expiresIn: '1h', keyid: SERVER_JWK_KEY_ID }),
    }),
  };

  response.writeHead(200, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    Pragma: 'no-cache',
    ...CORS_HEADERS,
  });
  response.write(JSON.stringify(responseBody, null, 2));
  response.end();
}

async function userinfoListener(request, response) {
  const userinfo = {
    sub: LOGGED_IN_USER_SUB,
    ...(LOGGED_IN_USER_EMAIL && { email: LOGGED_IN_USER_EMAIL }),
    ...(LOGGED_IN_USER_NAME && { name: LOGGED_IN_USER_NAME }),
  };

  response.writeHead(200, {
    'Content-Type': 'application/json',
    ...CORS_HEADERS,
  });
  response.write(JSON.stringify(userinfo, null, 2));
  response.end();
}

async function certsListener(request, response) {
  const keys = [{
    n: SERVER_JWK.n,
    e: SERVER_JWK.e,
    kid: SERVER_JWK_KEY_ID,
    kty: SERVER_JWK.kty,
    alg: 'RS256',
    use: 'sig',
  }];

  response.writeHead(200, {
    'Content-Type': 'application/json',
    ...CORS_HEADERS,
  });
  response.write(JSON.stringify(keys, null, 2));
  response.end();
}

async function getStaticAccessToken() {
  return Promise.resolve({
    access_token: 'super_token',
    token_type: 'Bearer',
    expires_in: 60 * 60,
  });
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

  return (await axios.post('https://oauth2.googleapis.com/token', params)).data;
}

async function refreshAccessToken() {
  const params = new URLSearchParams();
  params.append('grant_type', 'refresh_token');
  params.append('refresh_token', GOOGLE_REFRESH_TOKEN);
  params.append('scope', 'openid email profile https://www.googleapis.com/auth/cloud-platform');

  return (await axios.post('https://oauth2.googleapis.com/token', params, {
    auth: {
      username: GOOGLE_CLIENT_ID,
      password: GOOGLE_CLIENT_SECRET,
    },
  })).data;
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
server.on('error', (error) => {
  console.log(error);
});
