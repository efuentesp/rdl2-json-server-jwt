const fs = require("fs");
const bodyParser = require("body-parser");
const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const _ = require("lodash");

const server = jsonServer.create();
const router = jsonServer.router("./database.json");
const authdb = JSON.parse(fs.readFileSync("./auth.json", "UTF-8"));

server.use(bodyParser.urlencoded({ extended: true }));
server.use(bodyParser.json());
server.use(jsonServer.defaults());

const SECRET_KEY = "123456789";

const expiresIn = "1h";

// Create a token from a payload
function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

// Verify the token
function verifyToken(token) {
  return jwt.verify(
    token,
    SECRET_KEY,
    (err, decode) => (decode !== undefined ? decode : err)
  );
}

// Check if the user exists in database
function isAuthenticated({ email, password }) {
  return (
    authdb.users.findIndex(
      user => user.email === email && user.password === password
    ) !== -1
  );
}

function findUserInfo(email) {
  var permissions = [];
  const user = _.find(authdb.users, u => u.email === email);
  const role = _.find(authdb.roles, r => r.id === user.roleId);
  const permission_assignment = _.filter(
    authdb.permission_assignment,
    a => a.roleId === user.roleId
  );
  permission_assignment.forEach(pa => {
    permissions.push(_.find(authdb.permissions, p => p.id === pa.permissionId));
  });
  const user_info = {
    user: { username: user.username, email: user.email, role: role.name },
    permissions
  };

  return user_info;
}

server.post("/auth/login", (req, res) => {
  const { email, password } = req.body;
  if (isAuthenticated({ email, password }) === false) {
    const status = 401;
    const message = "Incorrect email or password";
    res.status(status).json({ status, message });
    return;
  }
  const user_info = findUserInfo(email);
  const access_token = createToken(user_info);
  res.status(200).json({ access_token });
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
  if (
    req.headers.authorization === undefined ||
    req.headers.authorization.split(" ")[0] !== "Bearer"
  ) {
    const status = 401;
    const message = "Error in authorization format";
    res.status(status).json({ status, message });
    return;
  }
  try {
    verifyToken(req.headers.authorization.split(" ")[1]);
    next();
  } catch (err) {
    const status = 401;
    const message = "Error access_token is revoked";
    res.status(status).json({ status, message });
  }
});

server.use(router);

server.listen(3000, () => {
  console.log("Run Auth API Server (port: 3000)");
});
