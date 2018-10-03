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
    user: {
      username: user.username,
      display_name: user.display_name,
      email: user.email,
      user_enabled: user.enabled,
      role: role.name,
      role_enabled: role.enabled
    },
    permissions
  };

  return user_info;
}

function isPermissionFound(token, permission) {
  const permission_found = _.find(
    token.permissions,
    p => p.code === permission
  );
  return typeof permission_found == "undefined" ? false : true;
}

function hasAuthority(resource, operation, user_info) {
  const permission = resource + ":" + operation;
  const all_operations = resource + ":*";
  const superuser = "*:*";

  //console.log(permission);

  if (!isPermissionFound(user_info, permission)) {
    if (!isPermissionFound(user_info, all_operations)) {
      if (!isPermissionFound(user_info, superuser)) {
        return false;
      }
    }
  }
  return true;
}

server.post("/auth/v1/login", (req, res) => {
  const { email, password } = req.body;
  if (isAuthenticated({ email, password }) === false) {
    res
      .status(401)
      .json({ status: 401, message: "Incorrect email or password" });
    return;
  }
  const user_info = findUserInfo(email);
  const access_token = createToken(user_info.user);
  res.status(200).json({ access_token });
});

server.get("/auth/v1/user", (req, res) => {
  if (
    req.headers.authorization === undefined ||
    req.headers.authorization.split(" ")[0] !== "Bearer"
  ) {
    res
      .status(401)
      .json({ status: 401, message: "Error in authorization format" });
    return;
  }

  const decoded_token = verifyToken(req.headers.authorization.split(" ")[1]);
  const user_info = findUserInfo(decoded_token.email);
  res
    .status(200)
    .json({ user: user_info.user, permissions: user_info.permissions });
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
  if (
    req.headers.authorization === undefined ||
    req.headers.authorization.split(" ")[0] !== "Bearer"
  ) {
    res
      .status(401)
      .json({ status: 401, message: "Error in authorization format" });
    return;
  }
  try {
    let resources = [];
    const decoded_token = verifyToken(req.headers.authorization.split(" ")[1]);
    resources.push(req._parsedOriginalUrl.path.split("/")[3].toUpperCase());
    console.log(req._parsedOriginalUrl.path.split("/"));
    console.log(req._parsedOriginalUrl.path.split("/").length);
    if (req._parsedOriginalUrl.path.split("/").length > 5) {
      if (req._parsedOriginalUrl.path.split("/")[5] !== "") {
        resources.push(req._parsedOriginalUrl.path.split("/")[5].toUpperCase());
      }
    }

    const user_info = findUserInfo(decoded_token.email);
    //console.log(decoded_token);

    //console.log(req._parsedOriginalUrl.path);
    //console.log(req.headers);
    //console.log(req.method);
    //console.log(req.url);
    //console.log(req.params);
    //console.log(req.query);
    //console.log(req.body);

    let operation;
    switch (req.method) {
      case "GET":
        operation = "READ";
        break;
      case "POST":
        operation = "CREATE";
        break;
      case "PUT":
        operation = "UPDATE";
        break;
      case "DELETE":
        operation = "DELETE";
        break;
      default:
        operation = "UNKNOWN";
    }

    resources.forEach(r => {
      if (!hasAuthority(r, operation, user_info)) {
        res.status(404).json({
          status: 404,
          message: `You don't have permission (${r}:${operation})`
        });
        return;
      }
    });

    next();
  } catch (err) {
    res
      .status(401)
      .json({ status: 401, message: "Error access_token is revoked" });
  }
});

server.use("/api/v1", router);

server.listen(3000, () => {
  console.log("Run Auth API Server (port: 3000)");
});
