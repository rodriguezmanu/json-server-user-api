const fs = require('fs');
const bodyParser = require('body-parser');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');

const server = jsonServer.create();
const router = jsonServer.router('./db.json');

server.use(bodyParser.urlencoded({ extended: true }));
server.use(bodyParser.json());
server.use(jsonServer.defaults());

const SECRET_KEY = '123456789';
const expiresIn = '24h';

/**
 * Create a token from a payload
 * @param {Object} payload
 */
function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

/**
 * Verify the token
 * @param {String} token
 */
function verifyToken(token) {
  return jwt.verify(token, SECRET_KEY, (err, decode) => decode || err);
}

/**
 * Check if the user exists in database
 * @param {String} email
 * @param {String} password
 * @returns {Boolean}
 */
function isAuthenticated({ email, password }) {
  const userdb = JSON.parse(fs.readFileSync('./db.json', 'UTF-8'));
  return userdb.users.find(user => user.email === email && user.password === password);
}

server.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = isAuthenticated({ email, password });

  if (user) {
    const userClone = Object.assign({}, user);
    delete userClone.password;

    const access_token = createToken(userClone);
    res.status(200).json({ access_token, ...userClone });
    return;
  }
  const status = 401;
  const message = 'Incorrect email or password';

  res.status(status).json({ status, message });
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
  if (!req.headers.authorization || req.headers.authorization.split(' ')[0] !== 'Bearer') {
    const status = 401;
    const message = 'Error in authorization format';

    res.status(status).json({ status, message });
    return;
  }
  try {
    verifyToken(req.headers.authorization.split(' ')[1]);
    next();
  } catch (err) {
    const status = 401;
    const message = 'Error access_token is revoked';

    res.status(status).json({ status, message });
  }
});

server.use(
  jsonServer.rewriter({
    '/auth/signup': '/users',
  })
);

server.use(router);

server.listen(3004, () => {
  console.log('Run API Server');
});
