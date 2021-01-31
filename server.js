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

const {
  SERVER_PRIVATE_KEY_FILE,
  GOOGLE_SERVICE_ACCOUNT_CREDENTIAL_FILE,
  GOOGLE_REFRESH_TOKEN_FILE,
  GOOGLE_CLIENT_SECRET_FILE,
  GOOGLE_ID_TOKEN_FILE,
  LOGGED_IN_USER_SUB,
  LOGGED_IN_USER_EMAIL,
  LOGGED_IN_USER_NAME,
  ISSUER,
} = process.env;

let {
  SERVER_PRIVATE_KEY,
  GOOGLE_SERVICE_ACCOUNT_CREDENTIAL,
  GOOGLE_ID_TOKEN,
  GOOGLE_REFRESH_TOKEN,
  GOOGLE_CLIENT_SECRET,
} = process.env;

if (SERVER_PRIVATE_KEY_FILE) {
  SERVER_PRIVATE_KEY = fs.readFileSync(SERVER_PRIVATE_KEY_FILE, 'ascii');
}
if (GOOGLE_SERVICE_ACCOUNT_CREDENTIAL_FILE) {
  GOOGLE_SERVICE_ACCOUNT_CREDENTIAL = fs.readFileSync(GOOGLE_SERVICE_ACCOUNT_CREDENTIAL_FILE, 'ascii');
}
if (GOOGLE_ID_TOKEN_FILE) {
  GOOGLE_ID_TOKEN = fs.readFileSync(GOOGLE_ID_TOKEN_FILE, 'ascii').trim();
}
if (GOOGLE_REFRESH_TOKEN_FILE) {
  GOOGLE_REFRESH_TOKEN = fs.readFileSync(GOOGLE_REFRESH_TOKEN_FILE, 'ascii').trim();
}
if (GOOGLE_CLIENT_SECRET_FILE) {
  GOOGLE_CLIENT_SECRET = fs.readFileSync(GOOGLE_CLIENT_SECRET_FILE, 'ascii').trim();
}

if (!SERVER_PRIVATE_KEY) {
  SERVER_PRIVATE_KEY = new NodeRSA().generateKeyPair().exportKey('pkcs1-private-pem');
}
const SERVER_JWK = pem2jwk(SERVER_PRIVATE_KEY);
const SERVER_JWK_KEY_ID = '0';

const DEFAULT_SUBJECT = 'default_subject';

const REFRESH_TOKEN = 'refresh_me';

const LISTEN_PORT = Number(process.env.LISTEN_PORT || 80);

const GOOGLE_SERVICE_ACCOUNT = GOOGLE_SERVICE_ACCOUNT_CREDENTIAL
  && JSON.parse(GOOGLE_SERVICE_ACCOUNT_CREDENTIAL);

if (!((GOOGLE_ID_TOKEN && GOOGLE_REFRESH_TOKEN && GOOGLE_CLIENT_SECRET)
  || (!GOOGLE_ID_TOKEN && !GOOGLE_REFRESH_TOKEN && !GOOGLE_CLIENT_SECRET))) {
  console.log('GOOGLE_ID_TOKEN, GOOGLE_REFRESH_TOKEN, and GOOGLE_CLIENT_SECRET must either all be defined or none must be defined');
  process.exit(1);
}

if (GOOGLE_SERVICE_ACCOUNT_CREDENTIAL && GOOGLE_ID_TOKEN) {
  console.log('Either use a GOOGLE_SERVICE_ACCOUNT_CREDENTIAL or a refresh token combination');
  process.exit(1);
}

let GOOGLE_ID_TOKEN_CLAIMS;

if (GOOGLE_ID_TOKEN) {
  const {
  // eslint-disable-next-line camelcase
    iss, azp, at_hash, iat, exp, ...userClaims
  } = jwt.decode(GOOGLE_ID_TOKEN);

  GOOGLE_ID_TOKEN_CLAIMS = { ...userClaims };
}

async function fetchAccessToken() {
  if (GOOGLE_SERVICE_ACCOUNT) {
    return getServiceAccountAccessToken();
  }

  if (GOOGLE_ID_TOKEN_CLAIMS) {
    return getRefreshAccessToken();
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
      case '/introspect':
        await introspectListener(request, response);
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
    introspection_endpoint: `${issuer}/introspect`,
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
      'offline_access',
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

  const redirectUri = new URL(url.searchParams.get('redirect_uri'));

  redirectUri.searchParams.append('code', 'code');
  if (state) {
    redirectUri.searchParams.append('state', state);
  }

  response.writeHead(302, {
    Location: redirectUri.toString(),
    ...CORS_HEADERS,
  });
  response.end();
}

async function tokenListener(request, response) {
  const requestParameters = await readPost(request);
  const clientId = requestParameters.client_id;
  const issuer = getIssuer(request);

  const idClaims = {
    iss: issuer,
    aud: clientId,
  };

  Object.assign(idClaims, { ...GOOGLE_ID_TOKEN_CLAIMS && { sub: GOOGLE_ID_TOKEN_CLAIMS.sub } });
  Object.assign(idClaims, { ...LOGGED_IN_USER_SUB && { sub: LOGGED_IN_USER_SUB } });
  Object.assign(idClaims, { ...!idClaims.sub && { sub: DEFAULT_SUBJECT } });

  const accessTokenData = await fetchAccessToken();

  const responseBody = {
    access_token: accessTokenData.access_token,
    token_type: accessTokenData.token_type,
    expires_in: accessTokenData.expires_in,
    ...(requestParameters.grant_type === 'authorization_code' && {
      refresh_token: REFRESH_TOKEN,
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
  const userinfo = {};

  if (GOOGLE_ID_TOKEN_CLAIMS) {
    Object.assign(userinfo, GOOGLE_ID_TOKEN_CLAIMS);
    delete userinfo.aud;
  }

  Object.assign(userinfo, { ...LOGGED_IN_USER_SUB && { sub: LOGGED_IN_USER_SUB } });
  Object.assign(userinfo, { ...LOGGED_IN_USER_EMAIL && { email: LOGGED_IN_USER_EMAIL } });
  Object.assign(userinfo, { ...LOGGED_IN_USER_NAME && { name: LOGGED_IN_USER_NAME } });
  Object.assign(userinfo, { ...!userinfo.sub && { sub: DEFAULT_SUBJECT } });

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

async function introspectListener(request, response) {
  let introspectBody;
  const { token } = await readPost(request);
  let myToken;
  try {
    myToken = jwt.verify(token, SERVER_PRIVATE_KEY, { algorithms: ['RS256'] });
  // eslint-disable-next-line no-empty
  } catch (err) { }

  if (myToken) {
    introspectBody = myToken;
    introspectBody.token_type = 'id_token';
  } else if (token === REFRESH_TOKEN) {
    introspectBody = {
      active: true,
      token_type: 'refresh_token',
    };
  } else if (GOOGLE_SERVICE_ACCOUNT || GOOGLE_ID_TOKEN_CLAIMS) {
    try {
      const tokenResponse = await axios.get(`https://oauth2.googleapis.com/tokeninfo?access_token=${token}`);
      introspectBody = {
        ...tokenResponse.data,
        active: true,
      };
      introspectBody.iss = getIssuer(request);
      introspectBody.token_type = 'access_token';
      delete introspectBody.aud;
      delete introspectBody.azp;
      delete introspectBody.expires_in;
      delete introspectBody.access_type;
    } catch (error) {
      introspectBody = { active: false };
    }
  } else {
    introspectBody = {
      active: true,
      token_type: 'access_token',
    };
  }

  Object.assign(introspectBody, { ...LOGGED_IN_USER_SUB && { sub: LOGGED_IN_USER_SUB } });
  Object.assign(introspectBody, { ...LOGGED_IN_USER_EMAIL && { email: LOGGED_IN_USER_EMAIL } });
  Object.assign(introspectBody, { ...LOGGED_IN_USER_NAME && { name: LOGGED_IN_USER_NAME } });
  if (introspectBody.scope) {
    introspectBody.scope = introspectBody.scope.replace(/https:\/\/www\.googleapis\.com\/auth\/userinfo\./g, '');
    introspectBody.scope = introspectBody.scope.concat(' offline_access');
  }

  response.writeHead(200, {
    'Content-Type': 'application/json',
    ...CORS_HEADERS,
  });
  response.write(JSON.stringify(introspectBody, null, 2));
  response.end();
}

async function getStaticAccessToken() {
  return Promise.resolve({
    access_token: 'default_access_token',
    token_type: 'Bearer',
    expires_in: 60 * 60,
  });
}

async function getServiceAccountAccessToken() {
  const authenticationJWT = jwt.sign({
    scope: 'https://www.googleapis.com/auth/cloud-platform',
  }, GOOGLE_SERVICE_ACCOUNT.private_key, {
    algorithm: 'RS256',
    issuer: GOOGLE_SERVICE_ACCOUNT.client_email,
    audience: GOOGLE_SERVICE_ACCOUNT.token_uri,
    expiresIn: '5m',
  });

  const params = new URLSearchParams();
  params.append('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer');
  params.append('assertion', authenticationJWT);

  return (await axios.post('https://oauth2.googleapis.com/token', params)).data;
}

async function getRefreshAccessToken() {
  const params = new URLSearchParams();
  params.append('grant_type', 'refresh_token');
  params.append('refresh_token', GOOGLE_REFRESH_TOKEN);
  params.append('scope', 'openid email profile https://www.googleapis.com/auth/cloud-platform');

  return (await axios.post('https://oauth2.googleapis.com/token', params, {
    auth: {
      username: GOOGLE_ID_TOKEN_CLAIMS.aud,
      password: GOOGLE_CLIENT_SECRET,
    },
  })).data;
}

function readPost(request) {
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

function getIssuer(request) {
  const url = new URL(request.url, `http://${request.headers.host}`);

  let issuer = ISSUER;
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
