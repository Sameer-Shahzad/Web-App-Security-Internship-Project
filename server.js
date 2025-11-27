const express = require("express");
const bodyParser = require("body-parser");
const validator = require("validator");        // Week 2: Input validation library
const bcrypt = require("bcrypt");              // Week 2: Password hashing
const jwt = require("jsonwebtoken");           // Week 2: Token-based authentication
const helmet = require("helmet");              // Week 2: Secure HTTP headers
const session = require("express-session");

// Week 3: Adding Winston logging
const winston = require("winston");  

// Week 3: Logger Setup
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

const USERS = {};
let userIdCounter = 1;

const initializeUsers = async () => {
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

app.use(helmet());     

app.use(bodyParser.urlencoded({ extended: false, limit: "10kb" }));

// Week 3: Logging application start
logger.info("Application middleware initialized");

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

const verifyToken = (req, res, next) => {
  const token = req.session.token;

  if (!token) {
    // Week 3: Logging unauthorized access
    logger.warn("Unauthorized access attempt detected");

    return res.status(401).render("login", { message: "Please login first", messageType: "error" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);     
    req.userId = decoded.id;
    req.userUsername = decoded.username;
    req.isAdmin = decoded.isAdmin;

    next();
  } catch (err) {
    logger.error("Invalid or expired token detected");   // Week 3 logging
    
    req.session.token = null;
    return res.status(403).render("login", {
      message: "Session expired. Please login again",
      messageType: "error",
    });
  }
};

const validateEmail = (email) => {
  return validator.isEmail(email);        
};

const validateUsername = (username) => {
  return /^[a-zA-Z0-9_]{3,20}$/.test(username);
};

const validatePassword = (password) => {
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/.test(password);
};

app.get("/", (req, res) => {
  logger.info("Homepage accessed");   // Week 3 logging

  if (req.session.token) {
    try {
      const decoded = jwt.verify(req.session.token, JWT_SECRET);
      if (decoded.isAdmin) {
        return res.redirect("/admin");
      }
    } catch (err) {}
    return res.redirect("/profile");
  }
  res.render("login", { message: "", messageType: "" });
});

app.get("/login", (req, res) => {
  logger.info("Login page opened"); // Week 3 logging
  res.render("login", { message: "", messageType: "" });
});

app.post("/login", async (req, res) => {
  try {
    let { username, password } = req.body;

    username = validator.trim(username);      
    password = validator.trim(password);      

    if (!username || !password) {
      logger.warn("Login failed: Missing fields");   // Week 3 logging

      return res.status(400).render("login", {
        message: "Username and password are required",
        messageType: "error",
      });
    }

    if (username.length < 3 || username.length > 20) {
      logger.warn("Login failed: Invalid username format");

      return res.status(400).render("login", {
        message: "Invalid username format",
        messageType: "error",
      });
    }

    const user = USERS[username];

    if (!user) {
      logger.warn("Login failed: Invalid username");

      return res.status(401).render("login", {
        message: "Invalid credentials",
        messageType: "error",
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);   

    if (!passwordMatch) {
      logger.warn("Login failed: Wrong password");

      return res.status(401).render("login", {
        message: "Invalid credentials",
        messageType: "error",
      });
    }

    const token = jwt.sign(     
      {
        id: user.id,
        username: user.username,
        isAdmin: user.isAdmin,
      },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    req.session.token = token;
    req.session.username = user.username;
    req.session.isAdmin = user.isAdmin;

    logger.info(`User logged in: ${username}`);   // Week 3 logging

    return res.redirect("/profile");
  } catch (err) {
    logger.error("Login error occurred");

    return res.status(500).render("login", {
      message: "An error occurred. Please try again.",
      messageType: "error",
    });
  }
});

app.get("/signup", (req, res) => {
  logger.info("Signup page opened");
  res.render("signup", { message: "", messageType: "" });
});

app.post("/signup", async (req, res) => {
  try {
    let { username, email, password, confirmPassword } = req.body;

    username = validator.trim(username);               
    email = validator.trim(email).toLowerCase();       
    password = validator.trim(password);               
    confirmPassword = validator.trim(confirmPassword);

    if (!username || !email || !password || !confirmPassword) {
      logger.warn("Signup failed: Missing fields");

      return res.status(400).render("signup", {
        message: "All fields are required",
        messageType: "error",
      });
    }

    if (!validateUsername(username)) {
      logger.warn("Signup failed: Invalid username format");

      return res.status(400).render("signup", {
        message: "Username must be 3-20 alphanumeric characters",
        messageType: "error",
      });
    }

    if (!validateEmail(email)) {                       
      logger.warn("Signup failed: Invalid email");

      return res.status(400).render("signup", {
        message: "Invalid email address",
        messageType: "error",
      });
    }

    if (!validatePassword(password)) {
      logger.warn("Signup failed: Weak password");

      return res.status(400).render("signup", {
        message: "Password must be at least 8 characters with uppercase, lowercase, and number",
        messageType: "error",
      });
    }

    if (password !== confirmPassword) {
      logger.warn("Signup failed: Password mismatch");

      return res.status(400).render("signup", {
        message: "Passwords do not match",
        messageType: "error",
      });
    }

    if (USERS[username]) {
      logger.warn("Signup failed: Username exists");

      return res.status(409).render("signup", {
        message: "Username already exists",
        messageType: "error",
      });
    }

    const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);   

    USERS[username] = {
      id: userIdCounter++,
      username: username,
      email: email,
      password: hashedPassword,
      isAdmin: false,
    };

    logger.info(`New user registered: ${username}`);

    return res.render("signup", {
      message: "Signup successful! Please login.",
      messageType: "success",
    });
  } catch (err) {
    logger.error("Signup error occurred");

    return res.status(500).render("signup", {
      message: "An error occurred. Please try again.",
      messageType: "error",
    });
  }
});

app.get("/profile", verifyToken, (req, res) => {
  const user = USERS[req.userUsername];
  res.render("profile", {
    user: user.username,
    email: user.email,
    isAdmin: user.isAdmin,
    userId: user.id,
  });
});

app.get("/admin", verifyToken, (req, res) => {
  if (!req.isAdmin) {
    logger.warn("Unauthorized admin page access");

    return res.status(403).render("access-denied", {
      username: req.userUsername,
      message: "You do not have admin privileges to access this page.",
    });
  }

  const usersList = Object.values(USERS).map((u) => ({
    id: u.id,
    username: u.username,
    email: u.email,
    isAdmin: u.isAdmin,
  }));

  res.render("admin", { users: usersList });
});

app.get("/users", verifyToken, (req, res) => {
  const usersList = Object.values(USERS).map((u) => ({
    username: u.username,
    email: u.email,
    isAdmin: u.isAdmin ? "Yes" : "No",
  }));

  res.render("users", { users: usersList });
});

app.get("/logout", (req, res) => {
  logger.info("User logged out"); // Week 3 logging

  req.session.destroy((err) => {
    if (err) {
      logger.error("Logout error");

      return res.status(500).send("Error logging out");
    }
    res.redirect("/login");
  });
});

app.use((req, res) => {
  logger.warn("404 error triggered"); // Week 3 logging

  res.status(404).render("login", {
    message: "Page not found",
    messageType: "error",
  });
});

app.use((err, req, res, next) => {
  logger.error("Unhandled application error detected"); // Week 3 logging

  res.status(err.status || 500).render("login", {
    message: "An error occurred. Please try again.",
    messageType: "error",
  });
});

const startServer = async () => {
  await initializeUsers();

  logger.info("Server started successfully"); // Week 3 logging

  app.listen(port, () => {
    console.log(`App running at http://localhost:${port}`);
    console.log(`Admin: admin / admin123`);
    console.log(`User: testuser / user123`);
  });
};

startServer();

// Week 3: Security Checklist (Only comment)
// - Validate all inputs
// - Use HTTPS
// - Hash & salt passwords
// - Enable helmet
// - Implement logging
// - Secure cookies
