/* eslint-disable no-console */
/* eslint-disable no-use-before-define */
const fs = require('fs');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const { pem2jwk } = require('pem-jwk');
const NodeRSA = require('node-rsa');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const nocache = require('nocache');
const mustacheExpress = require('mustache-express');

const app = express();

app.use(cors({
  allowedHeaders: 'Authorization',
  methods: 'HEAD,GET,POST',
}));
app.use(express.urlencoded());
app.use(nocache());
app.set('json spaces', 2);
app.set('etag', false);
app.set('x-powered-by', false);
app.set('views', './views');
app.engine('html', mustacheExpress());
app.set('view engine', 'html');

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

const REFRESH_TOKEN = crypto.createHash('sha256').update([
  'LOGGED_IN_USER_SUB',
  'LOGGED_IN_USER_NAME',
  'LOGGED_IN_USER_EMAIL',
  'GOOGLE_SERVICE_ACCOUNT_CREDENTIAL',
  'SERVER_PRIVATE_KEY',
  'GOOGLE_ID_TOKEN',
  'GOOGLE_REFRESH_TOKEN',
  'GOOGLE_CLIENT_SECRET',
  'LISTEN_PORT',
].join()).digest('base64');

// will no longer be needed in Express.js 5
function runAsyncWrapper(callback) {
  return (req, res, next) => {
    callback(req, res, next)
      .catch(next);
  };
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

app.get('/.well-known/openid-configuration', (req, res) => {
  const issuer = getIssuer(req);

  const configuration = {
    issuer,
    authorization_endpoint: `${issuer}/auth`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    introspection_endpoint: `${issuer}/introspect`,
    jwks_uri: `${issuer}/certs`,
    check_session_iframe: `${issuer}/check_session_iframe.html`,
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

  res.json(configuration);
});

app.get('/auth', (req, res) => {
  const redirectUri = new URL(req.query.redirect_uri);

  redirectUri.searchParams.append('code', 'code');
  redirectUri.searchParams.append('session_state', REFRESH_TOKEN);

  if (req.query.state) {
    redirectUri.searchParams.append('state', req.query.state);
  }

  res.redirect(redirectUri);
});

app.post('/token', runAsyncWrapper(async (req, res) => {
  const issuer = getIssuer(req);

  if (req.body.grant_type === 'refresh_token' && req.body.refresh_token !== REFRESH_TOKEN) {
    res.status(400).json({ error: 'invalid_grant' });
    return;
  }

  const idClaims = {
    iss: issuer,
    aud: req.body.client_id,
  };

  Object.assign(idClaims, { ...GOOGLE_ID_TOKEN_CLAIMS && { sub: GOOGLE_ID_TOKEN_CLAIMS.sub } });
  Object.assign(idClaims, { ...LOGGED_IN_USER_SUB && { sub: LOGGED_IN_USER_SUB } });
  Object.assign(idClaims, { ...!idClaims.sub && { sub: DEFAULT_SUBJECT } });

  const accessTokenData = await fetchAccessToken();

  const responseBody = {
    access_token: accessTokenData.access_token,
    token_type: accessTokenData.token_type,
    expires_in: accessTokenData.expires_in,
    ...(req.body.grant_type === 'authorization_code' && {
      refresh_token: REFRESH_TOKEN,
      id_token: jwt.sign(idClaims, SERVER_PRIVATE_KEY, { algorithm: 'RS256', expiresIn: '1h', keyid: SERVER_JWK_KEY_ID }),
    }),
  };

  res.json(responseBody);
}));

app.get('/userinfo', (req, res) => {
  const userinfo = {};

  if (GOOGLE_ID_TOKEN_CLAIMS) {
    Object.assign(userinfo, GOOGLE_ID_TOKEN_CLAIMS);
    delete userinfo.aud;
  }

  Object.assign(userinfo, { ...LOGGED_IN_USER_SUB && { sub: LOGGED_IN_USER_SUB } });
  Object.assign(userinfo, { ...LOGGED_IN_USER_EMAIL && { email: LOGGED_IN_USER_EMAIL } });
  Object.assign(userinfo, { ...LOGGED_IN_USER_NAME && { name: LOGGED_IN_USER_NAME } });
  Object.assign(userinfo, { ...!userinfo.sub && { sub: DEFAULT_SUBJECT } });

  res.json(userinfo);
});

app.get('/certs', (req, res) => {
  const keys = [{
    n: SERVER_JWK.n,
    e: SERVER_JWK.e,
    kid: SERVER_JWK_KEY_ID,
    kty: SERVER_JWK.kty,
    alg: 'RS256',
    use: 'sig',
  }];

  res.json(keys);
});

app.post('/introspect', runAsyncWrapper(async (req, res) => {
  let introspectBody;
  const { token } = req.body;
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
      introspectBody.iss = getIssuer(req);
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

  res.json(introspectBody);
}));

app.get('/check_session_iframe.html', (req, res) => {
  res.render('check_session_iframe', { issuer: getIssuer(req) });
});

app.get('/deadend', (req, res) => {
  res.json(req.query);
});

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

  const { data } = await axios.post('https://oauth2.googleapis.com/token', params, {
    auth: {
      username: GOOGLE_ID_TOKEN_CLAIMS.aud,
      password: GOOGLE_CLIENT_SECRET,
    },
  });

  if (data.refresh_token) {
    GOOGLE_REFRESH_TOKEN = data.refresh_token;
  }

  return data;
}

function getIssuer(request) {
  const url = new URL(request.url, `http://${request.headers.host}`);

  let issuer = ISSUER;
  if (!issuer) {
    if (request.headers['x-forwarded-host']) {
      issuer = `${request.headers['x-forwarded-proto'].split(',')[0]}://${request.headers['x-forwarded-host'].split(',')[0]}`;
    } else {
      issuer = url.origin;
    }
  }
  return issuer;
}

app.listen(LISTEN_PORT, () => {
  console.log(`OIDC Redirect listening at http://localhost:${LISTEN_PORT}`);
});
