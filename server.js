// server.js
const jwt = require("jsonwebtoken");
const jsonServer = require("json-server");
const server = jsonServer.create();
const router = jsonServer.router("db.json");
const { db } = router;
const middlewares = jsonServer.defaults();
const JWT_SECRET_KEY = "json-server-auth-123456";
const JWT_EXPIRES_IN = "1d";
server.use(jsonServer.bodyParser);
server.use(middlewares);

function isAuthorized(req) {
  console.log("Inside isAuthorized ");
  const authHeader = req.header("Authorization");
  if (authHeader != undefined) {
    const tokenArr = authHeader.split(" ");
    if (tokenArr[1]) {
      try {
        const payload = jwt.verify(tokenArr[1], JWT_SECRET_KEY);

        if (!payload.role)
          return "role is missing in user data. At the time of signup don't forget to add role";
        const route = db.get("roleMapping").find({ route: req.path }).value();

        if (typeof route === undefined) return "No route found";

        /*
        No route has been defined for ${req.path}.  
        */
        if (!route) return "AUTHORIZED";
        console.log(
          `route is ${JSON.stringify(
            route,
            null,
            2
          )}. typeof route is ${typeof route}`
        );
        console.log(
          `route.roles is ${JSON.stringify(
            route.roles,
            null,
            2
          )}, typeof route.roles is ${typeof route.roles}`
        );
        console.log(
          `payload is ${JSON.stringify(
            payload,
            null,
            2
          )}. type is : ${typeof payload.role}`
        );
        if (route.roles.includes(payload.role)) {
          return "AUTHORIZED";
        } else {
          return "Unauthorized to view this resource";
        }
      } catch (err) {
        return err.message;
      }
    } else {
      return "JSON web token missing";
    }
  } else {
    return "Authorization header is empty";
  }
}

server.post("/signup", (req, res) => {
  console.log("Inside signup");
  const { username, password, ...rest } = req.body;
  console.log(req.body);
  const existingUser = db.get("users").find({ username }).value();
  if (existingUser) {
    res.status(400).jsonp("username already exists");
    return;
  }

  db.get("users").insert(req.body).write();
  console.log(`Printing after inserting`);
  console.log(db.get("users").find().value());

  res.json(req.body);
});

server.post("/login", (req, res) => {
  console.log("Inside login");
  const { username, password } = req.body;
  console.log(req.body);
  const user = db.get("users").find({ username }).value();
  if (user.password !== password) {
    res.status(400).jsonp("Invalid credentials");
    return;
  }

  var token = jwt.sign({ username, role: user.role }, JWT_SECRET_KEY, {
    expiresIn: JWT_EXPIRES_IN,
    subject: String(user.id),
  });

  res.json({ message: "login successful", token });
});

server.use((req, res, next) => {
  console.log(`req.path is ${req.path}`);
  const authorizationResult = isAuthorized(req);
  console.log(`authorizationResult: ${authorizationResult}`);
  if (authorizationResult === "AUTHORIZED" || req.path === "/login") {
    next(); // continue to JSON Server router
  } else {
    res.status(401);
    res.send({ message: authorizationResult });
  }
});

server.use(router);

server.listen(5000, () => {
  console.log("JSON Server is running");
});
