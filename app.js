const express = require("express");
// For session
const session = require("express-session");
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

// Create the instance of express
const app = express();



// Assign the server port saved in .env file
const PORT = process.env.PORT;



// List for origins to access this server
const allowedOrigins = [
  "http://localhost:8510",  // For this server
  "http://localhost:7654",  // For Task Management App
  "https://clever-dango-da3acc.netlify.app/",   // For Film Finder App on Netlify
  "http://localhost:7678",  
  "https://supabase.com",   // For DB on Supabase
  "https://github-desktop-test-1.onrender.com", // This server on Render
  "https://taskschedulemgtapp.netlify.app/",    // Task Management App on Netlify
  "https://mikan-chef.netlify.app/",            // Mikan Chef App on Netlify
];
// Configure options of CORS
const corsOptions = {
  origin: function (origin, callback) {
    // console.log('Incoming request origin:', origin); // Log the origins
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);                       // Allow origins in "allowedOrigins" list
    } else {
      callback(new Error("Not allowed by CORS")); // Disallow origin
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE"],          // Allowed methods
  allowedHeaders: ["Content-Type", "Authorization"],  // Allowed headers
  credentials: true,                                  // Allow credentials
};
// Set the options configured above to CORS
app.use(cors(corsOptions));


// Middleware to set up session
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }, // Set true if using HTTPS!!!
}));


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



// PostgreSQL connection settings
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
  ssl: { rejectUnauthorized: false },
  keepAlive: true,
});
// Check the connection with DB on Supabase
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



// Middleware to validate JWT
const authenticateToken = (req, res, next) => {
  console.log("cookies: ", req.cookies.token);
  console.log("token saved in cookie: ", req.cookies.token);
  // Enable to handle req patters either req.cookies, req.cookies.token, req.header['Authorization'], or req.headers['Authorization'].split(' ')[1]
  // ...split(' ').[1] takes req.headers - "Authorization: Bearer JWT_TOKEN". So, take index 1 from Bearer = 0, _ , JWT_TOKEN = 1
  const token = req.cookies?.token || req.headers['Authorization']?.split(' ')[1];

  // CASE: no token
  if(!token) {
    res.locals.message = "Access denied.";
    return res.status(401).redirect('/login');
  }

  // Validate JWT token
  jwt.verify(token, SECRET_KEY, (err, user) => {
    // case: invalid token
    if(err) {
      res.locals.message = "Invalid JWT token.";
      return res.status(403).redirect('/login');
    }
    // case: valid token
    console.log("Passed JWT token validation!");
    req.user = user;
    next();
  });
};



// Disable any kind of caches without configuration 
app.use((req, res, next) => {
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, private"
  );
  next();
});






// ROUTES
// redirect "/" to "/login"
app.get('/', (req, res) => {
  res.redirect('/login');
});


// Display Login Page
app.get("/login", (req, res) => {
  console.log("Session Data: ", req.session.pageData);
  const prevData = req.session.pageData;
  
  if(prevData) {
    res.locals.login = prevData.login;
    res.locals.page = prevData.page;
    res.locals.message = prevData.message;
    res.locals.username = prevData.username;
  } else {
    res.locals.login = false;
    res.locals.page = "login";
    res.locals.message = "Please sing up if you don't have a user account yet.";
    res.locals.username = "none";
  }
  
  res.render("login", {
    title: "Log In",
  });
});


// Display Signup Page
app.get("/signup", (req, res) => {
  console.log("Session Data: ", req.session.pageData);
  const prevData = req.session.pageData;
  // Any cases to use session????
  if(prevData) {
    res.locals.login = prevData.login;
    res.locals.page = prevData.page;
    res.locals.message = prevData.message;
    res.locals.username = prevData.username;
  } else {
    res.locals.login = false;
    res.locals.page = "signup";
    res.locals.message = "Please log in if you already signed up.";
    res.locals.username = "none";
  }

  res.render("signup", {
    title: "Sign Up",
  });
});


// Display Menu Page
app.get("/menu", authenticateToken, (req, res) => {
  console.log("Path to app.get('/menu');");
  console.log("req.user from token check middleware: ", req.user);
  // Any cases to use session???
  // console.log("Session Data: ", req.session.pageData);
  // const prevData = req.session.pageData;
  // if(prevData) {
  //   res.locals.login = prevData.login;
  //   res.locals.page = prevData.page;
  //   res.locals.message = prevData.message;
  //   res.locals.username = prevData.username;
  // } else 
  {
    res.locals.login = true;
    res.locals.page = "menu";
    res.locals.message = "Welcome, " + req.user.username + "! You can access one of apps listed below.";
    res.locals.username = req.user.username;
  }

  res.render("menu", {
    title: "Menu Page",
  });
});


// Admin Page Path
app.get('/admin', authenticateToken, (req, res) => {
  console.log("Path to app.get('/admin');");
  
  res.locals.page = "admin";
  res.locals.message = "You can add or remove the apps where users can access here.";
  res.locals.username = req.user.username;
  // Needs to re-assign later
  res.locals.appList = []; 
  res.render("adminMenu", {
    title: "Admin Page",
  });
});


// Login Process:
// 1. Check if the target user account based on the input
// 2. If there is matching one in DB, go to the main page
// 2. If there is no matching account in DB, stay in Login Page with the appropriate message
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  console.log("Server receive a request: ", email, " : ", password);

  // Check if the username exists in DB
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

      // Check if the email is in DB
      if (results.rows.length < 1) {
        // CASE: No matching email in DB

        // Move to login page with error message
        res.locals.login = false;
        res.locals.page = "login";
        res.locals.message = "Invalid username or password. Please try again.";
        res.locals.username = "none";
        return res.status(404).redirect('/login');
      } else {
        // CASE: FOUND the user info in DB

        // Check the returned user info from DB, and save it to "user"
        console.log("Login User info: ", results.rows[0]);
        const user = results.rows[0];

        // Compare hashed passwords
        const hash = user.password;
        bcrypt.compare(password, hash, (err, isEqual) => {
          // CASE: hash compare error
          if (err) {
            console.error(err);
            res.locals.login = false;
            res.locals.page = "login";
            res.locals.message = "Failed password validation - hash compare";
            res.locals.username = user.username;
            res.status(500).redirect('/login');
          }
          // Check if hashed passwords matches
          if (isEqual) {
            // CASE: FOUND the user info in DB

            // Generate JWT token
            const token = jwt.sign({ id: user.id, username: user.username, email: user.email }, SECRET_KEY, {
              expiresIn: "1h",
            });
            console.log("Token just generated: ", token);
            // Save cookie settings and JWT token into cookie
            res.cookie("token", token, { httpOnly: true, secure: false });

            // Move to Menu Page
            res.locals.login = true;
            res.locals.page = "menu";
            res.locals.message = "Welcome, " + user.username + "! You can access the menu now.\n\n" + "You received cookie token now: " + token;
            res.locals.username = user.username;
            res.status(200).redirect('/menu');
          } else {
            // CASE: Not found the target user info in DB
            res.locals.login = false;
            res.locals.page = "login";
            res.locals.message = "No such user. Please check username and password and try again.";
            res.locals.username = "none";
            res.status(404).redirect('/login');
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
    // Input Check
    console.log("Server receive a request 1: ", username, " : ", email, " : ", password);

    // Check if input username or email already exist in DB
    pool.query(
      "SELECT * FROM users WHERE username = $1 OR email = $2",
      [username, email],
      (error, results) => {
        if (error) {
          console.error("Server error: ", error);
          res.locals.message = "Server error: " + error;
          res.locals.login = false;
          res.locals.page = "signup";
          res.locals.username = "none";
          return res.status(500).redirect('/signup');
        }

        // Check if any duplicates exist in DB
        if (results.rows.length > 0) {
          // CASE: duplicate user info in DB
          console.log("Duplicates found in DB!");
          res.locals.message = "Either username or email is already registered. Please try with different username and email.";
          res.locals.login = false;
          res.locals.page = "signup";
          res.locals.username = "none";
          return res.status(400).redirect('/signup');
        } else {
          // CASE: No duplicates found in DB
          console.log("No duplicates found in DB.");
          next();
        }
      }
    );
  },
  // Add user account to DB based on the input
  (req, res, next) => {    
    const { username, email, password } = req.body;

    // Hash the password for security
    const saltRounds = 10;
    bcrypt.hash(password, saltRounds, (err, hash) => {
      if (err) {
        console.error("Failed to hashing password: ", err);
        res.locals.message = "Hashing password failed...";
        res.locals.login = false;
        res.locals.page = "signup";
        res.locals.username = "none";
        return res.status(500).redirect('/signup');
      }
      console.log("Password hashed successfully: ", hash);
      
      // Insert new user account info into DB
      pool.query(
        "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *",
        [username, email, hash],
        (error, results) => {
          if (error) {
            console.error("Server error: ", error);
            res.locals.message = "Server error: " + error;
            res.locals.login = false;
            res.locals.page = "signup";
            res.locals.username = "none";
            return res.status(500).redirect('/signup');
          }

          // Check the returned data from DB and assign the user info added as user
          console.log("Newly created use account is: ", results.rows);
          const user = results.rows[0];

          // Generate JWT token
          const token = jwt.sign({ id: user.id, username: user.username, email: user.email }, SECRET_KEY, {
            expiresIn: "1h",
          });
          // Save cookie settings with JWT token
          res.cookie("token", token, { httpOnly: true, secure: false });
          
          // Move to Menu Page
          res.locals.message = "Registered your user account successfully.";
          res.locals.login = true;
          res.locals.page = "menu";
          res.locals.username = user.username;
          return res.status(200).redirect('/menu');
        }
      );
    });
  }
);

// Process Logout
app.post("/logout", (req, res) => {
  res.clearCookie("token");
  req.session.pageData = {
    login: false,
    page: "login",
    message: "Logged out successfully",
    username: "none",
  };
  // res.locals.login = false;
  // res.locals.page = "login";
  // res.locals.message = "Logged out successfully!";
  // res.locals.username = "none";

  console.log("Logged out");
  res.status(200).redirect('/login');
});





app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});
