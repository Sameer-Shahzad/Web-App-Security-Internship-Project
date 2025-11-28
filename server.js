const express = require("express");
const bodyParser = require("body-parser");

// Week 2: Input validation library
const validator = require("validator");

// Week 2: Password hashing
const bcrypt = require("bcrypt");

// Week 2: Token-based authentication
const jwt = require("jsonwebtoken");

// Week 2: Secure HTTP headers
const helmet = require("helmet");

const session = require("express-session");

// Week 3: Logging library
const winston = require("winston");

// Week 3: Logger setup
const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "security.log" })
  ]
});

const app = express();
const port = 3000;

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-in-production";
const BCRYPT_ROUNDS = 10;

// Week 2: User storage with hashed passwords
const USERS = {};
let userIdCounter = 1;

const initializeUsers = async () => {
  // Week 2: Hashing default admin/user passwords
  const adminPassword = await bcrypt.hash("admin123", BCRYPT_ROUNDS);
  const userPassword = await bcrypt.hash("user123", BCRYPT_ROUNDS);

  USERS["admin"] = {
    id: userIdCounter++,
    username: "admin",
    email: "admin@example.com",
    password: adminPassword,
    isAdmin: true,
  };

  USERS["testuser"] = {
    id: userIdCounter++,
    username: "testuser",
    email: "test@example.com",
    password: userPassword,
    isAdmin: false,
  };
};

// Week 2: Secure HTTP headers enabled
app.use(helmet());

// Week 2: Parsing inputs safely
app.use(bodyParser.urlencoded({ extended: false, limit: "10kb" }));

// Week 3: Logging when middleware loads
logger.info("Application middleware initialized");

// Week 2: Secure session handling
app.use(
  session({
    secret: JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 3600000,
    },
  })
);

app.set("view engine", "ejs");
app.use(express.static("public"));

// Week 2: Token verification middleware
// Week 3: Logging unauthorized access
const verifyToken = (req, res, next) => {
  const token = req.session.token;

  if (!token) {
    logger.warn("Unauthorized access attempt detected");   // Week 3
    return res.status(401).render("login", { message: "Please login first", messageType: "error" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET); // Week 2
    req.userId = decoded.id;
    req.userUsername = decoded.username;
    req.isAdmin = decoded.isAdmin;

    next();
  } catch (err) {
    logger.error("Invalid or expired token detected"); // Week 3

    req.session.token = null;
    return res.status(403).render("login", {
      message: "Session expired. Please login again",
      messageType: "error",
    });
  }
};

// Week 2: Email validation
const validateEmail = (email) => validator.isEmail(email);

// Week 2: Username validation
const validateUsername = (username) => /^[a-zA-Z0-9_]{3,20}$/.test(username);

// Week 2: Password validation
const validatePassword = (password) => /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/.test(password);


// Week 3: Logging homepage access
app.get("/", (req, res) => {
  logger.info("Homepage accessed"); // Week 3

  if (req.session.token) {
    try {
      const decoded = jwt.verify(req.session.token, JWT_SECRET);
      if (decoded.isAdmin) return res.redirect("/admin");
    } catch (err) {}
    return res.redirect("/profile");
  }
  res.render("login", { message: "", messageType: "" });
});


// Week 3: Logging login page open
app.get("/login", (req, res) => {
  logger.info("Login page opened");
  res.render("login", { message: "", messageType: "" });
});


// Week 2: Input validation, hashing check, JWT creation
// Week 3: Logging login success/failure
app.post("/login", async (req, res) => {
  try {
    let { username, password } = req.body;

    username = validator.trim(username);     // Week 2
    password = validator.trim(password);     // Week 2

    if (!username || !password) {
      logger.warn("Login failed: Missing fields");  // Week 3
      return res.status(400).render("login", { message: "Username and password are required", messageType: "error" });
    }

    if (username.length < 3 || username.length > 20) {
      logger.warn("Login failed: Invalid username format"); // Week 3
      return res.status(400).render("login", { message: "Invalid username format", messageType: "error" });
    }

    const user = USERS[username];
    if (!user) {
      logger.warn("Login failed: Invalid username"); // Week 3
      return res.status(401).render("login", { message: "Invalid credentials", messageType: "error" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password); // Week 2
    if (!passwordMatch) {
      logger.warn("Login failed: Wrong password"); // Week 3
      return res.status(401).render("login", { message: "Invalid credentials", messageType: "error" });
    }

    const token = jwt.sign( // Week 2
      {
        id: user.id,
        username: user.username,
        isAdmin: user.isAdmin,
      },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    req.session.token = token;

    logger.info(`User logged in: ${username}`); // Week 3

    return res.redirect("/profile");
  } catch (err) {
    logger.error("Login error occurred"); // Week 3
    return res.status(500).render("login", { message: "An error occurred. Please try again.", messageType: "error" });
  }
});


// Week 3: Logging signup page open
app.get("/signup", (req, res) => {
  logger.info("Signup page opened");
  res.render("signup", { message: "", messageType: "" });
});


// Week 2: Full input validation + password hashing
// Week 3: Logging errors / success
app.post("/signup", async (req, res) => {
  try {
    let { username, email, password, confirmPassword } = req.body;

    username = validator.trim(username);         // Week 2
    email = validator.trim(email).toLowerCase(); // Week 2
    password = validator.trim(password);         // Week 2
    confirmPassword = validator.trim(confirmPassword);

    if (!username || !email || !password || !confirmPassword) {
      logger.warn("Signup failed: Missing fields"); // Week 3
      return res.status(400).render("signup", { message: "All fields are required", messageType: "error" });
    }

    if (!validateUsername(username)) {
      logger.warn("Signup failed: Invalid username format"); // Week 3
      return res.status(400).render("signup", { message: "Username must be 3-20 alphanumeric characters", messageType: "error" });
    }

    if (!validateEmail(email)) {
      logger.warn("Signup failed: Invalid email"); // Week 3
      return res.status(400).render("signup", { message: "Invalid email address", messageType: "error" });
    }

    if (!validatePassword(password)) {
      logger.warn("Signup failed: Weak password"); // Week 3
      return res.status(400).render("signup", { message: "Password must be at least 8 characters with uppercase, lowercase, and number", messageType: "error" });
    }

    if (password !== confirmPassword) {
      logger.warn("Signup failed: Password mismatch"); // Week 3
      return res.status(400).render("signup", { message: "Passwords do not match", messageType: "error" });
    }

    if (USERS[username]) {
      logger.warn("Signup failed: Username exists"); // Week 3
      return res.status(409).render("signup", { message: "Username already exists", messageType: "error" });
    }

    const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS); // Week 2

    USERS[username] = {
      id: userIdCounter++,
      username,
      email,
      password: hashedPassword,
      isAdmin: false,
    };

    logger.info(`New user registered: ${username}`); // Week 3

    return res.render("signup", { message: "Signup successful! Please login.", messageType: "success" });
  } catch (err) {
    logger.error("Signup error occurred"); // Week 3
    return res.status(500).render("signup", { message: "An error occurred. Please try again.", messageType: "error" });
  }
});


// Week 2: Token-protected route
app.get("/profile", verifyToken, (req, res) => {
  const user = USERS[req.userUsername];
  res.render("profile", {
    user: user.username,
    email: user.email,
    isAdmin: user.isAdmin,
    userId: user.id,
  });
});


// Week 2: Token verification + admin check
// Week 3: Logging unauthorized admin access
app.get("/admin", verifyToken, (req, res) => {
  if (!req.isAdmin) {
    logger.warn("Unauthorized admin page access"); // Week 3
    return res.status(403).render("access-denied", {
      username: req.userUsername,
      message: "You do not have admin privileges to access this page.",
    });
  }

  const usersList = Object.values(USERS);

  res.render("admin", { users: usersList });
});


// Week 2: Token verification
app.get("/users", verifyToken, (req, res) => {
  const usersList = Object.values(USERS);
  res.render("users", { users: usersList });
});


// Week 3: Logging logout
app.get("/logout", (req, res) => {
  logger.info("User logged out");
  req.session.destroy((err) => {
    if (err) {
      logger.error("Logout error");
      return res.status(500).send("Error logging out");
    }
    res.redirect("/login");
  });
});


// Week 3: Logging 404 errors
app.use((req, res) => {
  logger.warn("404 error triggered");
  res.status(404).render("login", { message: "Page not found", messageType: "error" });
});


// Week 3: Logging unhandled server errors
app.use((err, req, res, next) => {
  logger.error("Unhandled application error detected");
  res.status(err.status || 500).render("login", { message: "An error occurred. Please try again.", messageType: "error" });
});


// Week 2: Initialize users (hashed passwords)
// Week 3: Log successful server start
const startServer = async () => {
  await initializeUsers();

  logger.info("Server started successfully"); // Week 3

  app.listen(port, () => {
    console.log(`App running at http://localhost:${port}`);
    console.log(`Admin: admin / admin123`);
    console.log(`User: testuser / user123`);
  });
};

startServer();

// Week 3: Security Checklist (Comment Only)
// - Validate all inputs
// - Use HTTPS
// - Hash & salt passwords
// - Enable helmet
// - Implement logging
// - Secure cookies
