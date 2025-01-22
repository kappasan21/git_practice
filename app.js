const express = require("express");
// For PostgreSQL
const { Pool } = require("pg");
// What is this for?
const path = require("path");
// For cookies
const cookieParser = require("cookie-parser");
// For CORS
const cors = require("cors");
// For jwt - json web token - use token for secure authentication
const jwt = require("jsonwebtoken");
// For .evn file
require("dotenv").config();
// For bcrypt encryption
const bcrypt = require("bcrypt");

// Assign the server port saved in .env file
const PORT = process.env.PORT;

// Create the instance of express
const app = express();
// List for origins to access this server
const allowedOrigins = [
  "http://localhost:8510", // For this server
  "http://localhost:7654", // For Task Management App
  "https://supabase.com",
  "https://github-desktop-test-1.onrender.com", // Without trailing slash /
];
// Configure options of CORS
const corsOptions = {
  origin: function (origin, callback) {
    console.log('Incoming request origin:', origin); // Log the origin
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true); // Allow origin
    } else {
      callback(new Error("Not allowed by CORS")); // Disallow origin
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
};

// Set the options configured above to CORS
app.use(cors(corsOptions));
// Enable to use cookieParse
app.use(cookieParser());
// Enable to access public both server and browser
app.use(express.static("public"));
// Enable to transmit more than string data
app.use(express.urlencoded({ extended: true }));
// Enable to use ejs formatted files
app.set("view engine", "ejs");
// Assign views folder to save ejs files
app.set("views", path.join(__dirname, "views"));

// Secret key for JWT
const SECRET_KEY = process.env.JWT_SECRET_KEY;

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
  ssl: { rejectUnauthorized: false },
  keepAlive: true,
});
// Test the connection
(async () => {
  try {
    const client = await pool.connect();
    console.log('Connected to Supabase DB successfully!');
    const res = await client.query('SELECT NOW()');
    console.log(res.rows);
    client.release();
  } catch (error) {
    console.error('Error connecting to Supabase:', error);
  }
})();






// Disable any caches without configuration by code
app.use((req, res, next) => {
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, private"
  );
  next();
});

// ROUTES
// redirect to /login
app.get('/', (req, res) => {
  res.redirect('/login');
});


// Display Login Page
app.get("/login", (req, res) => {
  res.locals.login = false;
  res.locals.page = "login";
  res.locals.message = "Please sing up if you don't have a user account yet.";

  res.render("login", {
    title: "Log In",
    username: "---",
  });
});

// Display Signup Page
app.get("/signup", (req, res) => {
  res.locals.login = false;
  res.locals.page = "signup";
  res.locals.message = "Please log in if you already signed up.";

  res.render("signup", {
    title: "Sign Up",
    username: "---",
  });
});

// Display Menu Page
app.get("/menu", (req, res) => {
  console.log("app.get('/menu');");
  if (!res.locals.login) {
    res.redirect("/login");
    res.locals.page = "Log In";
    res.locals.message = "Please log in, again...";
  } else {
    res.locals.page = "";
    res.locals.message =
      "Welcome, " + req.cookies.username + "! You can access the menu now.";
    res.render("menu", {
      title: "Menu Page",
      username: req.cookies.username,
    });
  }
});

// Login Process:
// 1. Check if the target user account based on the input
// 2. If there is matching one in DB, go to the main page
// 2. If there is no matching account in DB, stay in Login Page with the appropriate message
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  console.log("Server receive a request: ", email, " : ", password);

  pool.query(
    "SELECT * FROM users WHERE email = $1",
    [email],
    (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).send({ msg: "DB error" });
      }

      // DB response check
      console.log("Response Array from DB: ", results.rows);
      console.log("1st item in Response Array: ", results.rows[0]);

      // Not found the email and password in DB
      if (results.rows.length < 1) {
        // Store locals variables into session later!!!
        res.locals.login = false;
        res.locals.page = "login";
        res.locals.message = "Invalid username or password. Please try again.";
        return res.status(404).render("login", {
          title: "Log In",
          username: "---",
          // username: results.rows[0].username,
        });
      } else {
        // Found the email in DB
        const user = results.rows[0];
        console.log("User found: ", user);

        // Check if hashed passwords match
        const hash = user.password;
        bcrypt.compare(password, hash, (err, isEqual) => {
          if (err) {
            console.error(err);
            res.status(500).send({ msg: "Server error" });
          }

          // Check if hash in DB and password match
          if (isEqual) {
            // Generate JWT token
            const token = jwt.sign({ id: user.id }, SECRET_KEY, {
              expiresIn: "1h",
            });
            console.log("Check point!!!");
            // Set cookie
            res.cookie("token", token, { httpOnly: true });
            console.log("token: ", token);
            // Set vars for GUI
            res.locals.login = true;
            res.locals.page = "";
            res.locals.message =
              "Welcome, " +
              user.username +
              "! You can access the menu now.\n\n" +
              "You received cookie token now: " +
              token;
            res.status(200).render("menu.ejs", {
              title: "Menu Page",
              username: user.username,
            });
          } else {
            res.locals.login = false;
            res.locals.page = "login";
            res.locals.message = "Failed to login!";
            res.status(404).render("login.ejs", {
              title: "Log In",
              username: "---",
            });
          }
        });
      }
    }
  );
});

app.post(
  "/signup",
  (req, res, next) => {
    const { username, email, password } = req.body;
    console.log(
      "Server receive a request 1: ",
      username,
      " : ",
      email,
      " : ",
      password
    );
    // Check if input username or email already exist in DB
    pool.query(
      "SELECT * FROM users WHERE username = $1 OR email = $2",
      [username, email],
      (error, results) => {
        if (error) {
          console.error(error);
          res.status(500).send({ msg: "Server error" });
        }

        if (results.rows.length > 0) {
          console.log("Duplicates found in DB!");
          res.locals.message =
            "Either username or email exists already. Please try with different username and email.";
          return res.redirect("/signup");
        } else {
          console.log("No duplicates found in DB.");
          next();
        }
      }
    );
  },
  (req, res, next) => {
    // Add user input info to DB
    const { username, email, password } = req.body;
    console.log(
      "Server receive a request 2: ",
      username,
      " : ",
      email,
      " : ",
      password
    );

    // Hash the password for security
    const saltRounds = 10;
    bcrypt.hash(password, saltRounds, (err, hash) => {
      if (err) {
        console.error({ msg: "Hashing password failed: " + err });
        res.locals.message = "Hashing password failed...";
        return res.status(500).redirect("/signup");
      }

      console.log("Password hashed successfully: ", hash);

      pool.query(
        "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id",
        [username, email, hash],
        (error, results) => {
          if (error) {
            console.error(error);
            res.status(500).send({ msg: "Server error" });
          }

          // create token!!!!
          res.locals.message = "Registered your user account successfully.";
          res.locals.login = true;
          return res.status(200).render("menu", {
            title: "Menu Page",
            username: username,
          });
        }
      );
    });
  }
);

// Process Logout
app.post("/logout", (req, res) => {
  res.locals.login = false;
  res.locals.page = "login";
  res.locals.message = "Logged out successfully!";
  res.locals.username = "";
  res.clearCookie("token");
  console.log("Logged out");

  // res.render("login", {
  //   title: "Log In",
  //   username: "---",
  // });
  res.redirect('/login');
});

app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});
