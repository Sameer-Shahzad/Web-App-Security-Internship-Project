const express = require("express");
const bodyParser = require("body-parser");
const validator = require("validator");        // Week 2: Input validation library
const bcrypt = require("bcrypt");              // Week 2: Password hashing
const jwt = require("jsonwebtoken");           // Week 2: Token-based authentication
const helmet = require("helmet");              // Week 2: Secure HTTP headers
const session = require("express-session");
const app = express();
const port = 3000;

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-in-production";
const BCRYPT_ROUNDS = 10;

const USERS = {};
let userIdCounter = 1;

const initializeUsers = async () => {
  const adminPassword = await bcrypt.hash("admin123", BCRYPT_ROUNDS);    // Week 2: Hashing default admin password
  const userPassword = await bcrypt.hash("user123", BCRYPT_ROUNDS);      // Week 2: Hashing demo user password

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

app.use(helmet());     // Week 2: Secure HTTP headers

app.use(bodyParser.urlencoded({ extended: false, limit: "10kb" }));

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
    return res.status(401).render("login", { message: "Please login first", messageType: "error" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);     // Week 2: Verifying token
    req.userId = decoded.id;
    req.userUsername = decoded.username;
    req.isAdmin = decoded.isAdmin;
    next();
  } catch (err) {
    req.session.token = null;
    return res.status(403).render("login", {
      message: "Session expired. Please login again",
      messageType: "error",
    });
  }
};

const validateEmail = (email) => {
  return validator.isEmail(email);        // Week 2: Email validation
};

const validateUsername = (username) => {
  return /^[a-zA-Z0-9_]{3,20}$/.test(username);
};

const validatePassword = (password) => {
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/.test(password);
};

app.get("/", (req, res) => {
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
  res.render("login", { message: "", messageType: "" });
});

app.post("/login", async (req, res) => {
  try {
    let { username, password } = req.body;

    username = validator.trim(username);      // Week 2: Sanitizing input
    password = validator.trim(password);      // Week 2: Sanitizing input

    if (!username || !password) {
      return res.status(400).render("login", {
        message: "Username and password are required",
        messageType: "error",
      });
    }

    if (username.length < 3 || username.length > 20) {
      return res.status(400).render("login", {
        message: "Invalid username format",
        messageType: "error",
      });
    }

    const user = USERS[username];

    if (!user) {
      return res.status(401).render("login", {
        message: "Invalid credentials",
        messageType: "error",
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);   // Week 2: Comparing hashed password

    if (!passwordMatch) {
      return res.status(401).render("login", {
        message: "Invalid credentials",
        messageType: "error",
      });
    }

    const token = jwt.sign(     // Week 2: Creating token after authentication
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

    return res.redirect("/profile");
  } catch (err) {
    return res.status(500).render("login", {
      message: "An error occurred. Please try again.",
      messageType: "error",
    });
  }
});

app.get("/signup", (req, res) => {
  res.render("signup", { message: "", messageType: "" });
});

app.post("/signup", async (req, res) => {
  try {
    let { username, email, password, confirmPassword } = req.body;

    username = validator.trim(username);               // Week 2: Sanitizing input
    email = validator.trim(email).toLowerCase();       // Week 2: Sanitizing input
    password = validator.trim(password);               // Week 2: Sanitizing input
    confirmPassword = validator.trim(confirmPassword);

    if (!username || !email || !password || !confirmPassword) {
      return res.status(400).render("signup", {
        message: "All fields are required",
        messageType: "error",
      });
    }

    if (!validateUsername(username)) {
      return res.status(400).render("signup", {
        message: "Username must be 3-20 alphanumeric characters",
        messageType: "error",
      });
    }

    if (!validateEmail(email)) {                       // Week 2: Email validation
      return res.status(400).render("signup", {
        message: "Invalid email address",
        messageType: "error",
      });
    }

    if (!validatePassword(password)) {
      return res.status(400).render("signup", {
        message: "Password must be at least 8 characters with uppercase, lowercase, and number",
        messageType: "error",
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).render("signup", {
        message: "Passwords do not match",
        messageType: "error",
      });
    }

    if (USERS[username]) {
      return res.status(409).render("signup", {
        message: "Username already exists",
        messageType: "error",
      });
    }

    const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);   // Week 2: Hashing password

    USERS[username] = {
      id: userIdCounter++,
      username: username,
      email: email,
      password: hashedPassword,
      isAdmin: false,
    };

    return res.render("signup", {
      message: "Signup successful! Please login.",
      messageType: "success",
    });
  } catch (err) {
    return res.status(500).render("signup", {
      message: "An error occurred. Please try again.",
      messageType: "error",
    });
  }
});

app.get("/profile", verifyToken, (req, res) => {
  if (req.isAdmin) {
    return res.redirect("/admin");
  }

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
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Error logging out");
    }
    res.redirect("/login");
  });
});

app.use((req, res) => {
  res.status(404).render("login", {
    message: "Page not found",
    messageType: "error",
  });
});

app.use((err, req, res, next) => {
  res.status(err.status || 500).render("login", {
    message: "An error occurred. Please try again.",
    messageType: "error",
  });
});

const startServer = async () => {
  await initializeUsers();

  app.listen(port, () => {
    console.log(`App running at http://localhost:${port}`);
    console.log(`Admin: admin / admin123`);
    console.log(`User: testuser / user123`);
  });
};

startServer();
