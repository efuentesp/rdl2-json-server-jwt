const fs = require("fs");
const bodyParser = require("body-parser");
const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const _ = require("lodash");
const lodashId = require("lodash-id");
const url = require("url");

const server = jsonServer.create();
const router = jsonServer.router("./database.json");
const router_auth = jsonServer.router("./auth.json");
const authdb = JSON.parse(fs.readFileSync("./auth.json", "UTF-8"));
const bizdb = JSON.parse(fs.readFileSync("./database.json", "UTF-8"));

const user_schema = require("./schemas/users");
const role_schema = require("./schemas/roles");
const permission_schema = require("./schemas/permissions");
const permission_assignment_schema = require("./schemas/permission_assignment");

server.use(bodyParser.urlencoded({ extended: true }));
server.use(bodyParser.json());
server.use(jsonServer.defaults());

const SECRET_KEY = "123456789";

const expiresIn = "1h";

_.mixin(lodashId);

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

server.post("/api/v1/auth/login", (req, res) => {
  const { email, password } = req.body;
  if (isAuthenticated({ email, password }) === false) {
    res
      .status(401)
      .json({ status: 401, message: "Error: Incorrect email or password" });
    return;
  }
  const user_info = findUserInfo(email);
  const access_token = createToken(user_info.user);
  res.status(200).json({ access_token });
});

server.get("/api/v1/auth/info", (req, res) => {
  if (
    req.headers.authorization === undefined ||
    req.headers.authorization.split(" ")[0] !== "Bearer"
  ) {
    res.status(400).json({
      status: 400,
      message: "Error: Access token is missing or invalid"
    });
    return;
  }

  try {
    const decoded_token = verifyToken(req.headers.authorization.split(" ")[1]);

    const user_info = findUserInfo(decoded_token.email);
    res
      .status(200)
      .json({ user: user_info.user, permissions: user_info.permissions });
  } catch (err) {
    res
      .status(401)
      .json({ status: 401, message: "Error: Access token is revoked" });
  }
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
  if (
    req.headers.authorization === undefined ||
    req.headers.authorization.split(" ")[0] !== "Bearer"
  ) {
    res.status(400).json({
      status: 400,
      message: "Error: Access token is missing or invalid"
    });
    return;
  }
  try {
    let resources = [];
    const decoded_token = verifyToken(req.headers.authorization.split(" ")[1]);
    const url_path = req._parsedUrl.path;
    const adr = `http://${req.headers.host}${url_path}`;

    let q = url.parse(adr, true);

    const auth_entities = Object.keys(authdb);
    const biz_entities = Object.keys(bizdb);
    const entities = _.union(auth_entities, biz_entities);
    const pathname_tokens = q.pathname.split("/");
    resources = _.intersection(entities, pathname_tokens);

    if (q.query._embed !== undefined) {
      resources.push(q.query._embed.toUpperCase());
    }

    if (q.query._expand !== undefined) {
      resources.push(q.query._expand.toUpperCase());
    }

    const user_info = findUserInfo(decoded_token.email);

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
      case "PATCH":
        operation = "UPDATE";
        break;
      case "DELETE":
        operation = "DELETE";
        break;
      default:
        operation = "UNKNOWN";
    }

    resources.forEach(r => {
      if (!hasAuthority(r.toUpperCase(), operation, user_info)) {
        res.status(404).json({
          status: 404,
          message: `You don't have permission (${r.toUpperCase()}:${operation})`
        });
        return;
      }
    });

    let error_messages = [];

    let validation_result = { error: null, value: null };
    if (req.method === "POST" || req.method === "PUT") {
      switch (resources[0]) {
        case "users":
          validation_result = user_schema.validate(req.body);
          if (validation_result.error === null) {
            const role = _.find(authdb.roles, r => r.id === req.body.roleId);
            if (role === undefined) {
              error_messages.push(
                `Role id "${req.body.roleId}" doesn't exist.`
              );
              res.status(400).json({
                status: 400,
                message: error_messages
              });
              return;
            }
          }
          break;

        case "roles":
          validation_result = role_schema.validate(req.body);
          break;

        case "permissions":
          validation_result = permission_schema.validate(req.body);
          break;

        case "permission_assignment":
          validation_result = permission_assignment_schema.validate(req.body);
          if (validation_result.error === null) {
            const role = _.find(authdb.roles, r => r.id === req.body.roleId);
            if (role === undefined) {
              error_messages.push(
                `Role id "${req.body.roleId}" doesn't exist.`
              );
              res.status(400).json({
                status: 400,
                message: error_messages
              });
              return;
            }
            const permission = _.find(
              authdb.permissions,
              p => p.id === req.body.permissionId
            );
            if (permission === undefined) {
              error_messages.push(
                `Permission id "${req.body.permissionId}" doesn't exist.`
              );
              res.status(400).json({
                status: 400,
                message: error_messages
              });
              return;
            }
          }
          break;
      }
    }

    if (validation_result.error !== null) {
      validation_result.error.details.forEach(err => {
        error_messages.push(err.message);
      });
      console.log(error_messages);

      res.status(400).json({
        status: 400,
        message: error_messages
      });
      return;
    }

    next();
  } catch (err) {
    res
      .status(401)
      .json({ status: 401, message: "Error: Access token is revoked" });
  }
});

// server.get("/auth/v1/users", (req, res) => {
//   const users = _.filter(authdb.users);
//   res.status(200).json({ users });
// });

// server.post("/auth/v1/users", (req, res) => {
//   const { username, display_name, email, password, enabled, roleId } = req.body;
//   const user = _.insert(authdb.users, {
//     username,
//     display_name,
//     email,
//     password,
//     enabled,
//     roleId
//   });
//   res.status(200).json({ user });
// });

// server.get("/auth/v1/roles", (req, res) => {
//   const roles = _.filter(authdb.roles);
//   res.status(200).json({ roles });
// });

// server.get("/auth/v1/permissions", (req, res) => {
//   const permissions = _.filter(authdb.permissions);
//   res.status(200).json({ permissions });
// });

server.get("/api/v1/auth/roles/:roleId/permissions", (req, res) => {
  let permissions = [];
  const permission_assignment = _.filter(
    authdb.permission_assignment,
    a => a.roleId.toString() === req.params.roleId.toString()
  );
  permission_assignment.forEach(pa => {
    permissions.push(_.find(authdb.permissions, p => p.id === pa.permissionId));
  });
  res.status(200).json({ permissions });
});

server.use("/api/v1/auth", router_auth);
server.use("/api/v1", router);
//server.use("/api/auth/v1", router_auth);

server.listen(3000, () => {
  console.log("Run Auth API Server (port: 3000)");
});
