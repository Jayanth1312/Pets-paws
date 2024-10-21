const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use('/public', express.static(path.join(__dirname, "public")));
app.use('/assets', express.static(path.join(__dirname, 'assets')));

app.use(express.json());
app.use(
  session({
    secret: "pets_home",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false },
  })
);

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "root",
  database: "pets",
});

db.connect((err) => {
  if (err) {
    console.error("Database connection error:", err);
    throw err;
  }
  console.log("Connected to database");
});

app.post("/signup", async (req, res) => {
  console.log("Signup request received:", {
    username: req.body.username,
    email: req.body.mail,
  });

  try {
    const { username, mail, password } = req.body;

    if (!username || !mail || !password) {
      return res.status(400).send("All fields are required");
    }

    const checkUser = "SELECT * FROM users WHERE email = ?";
    db.query(checkUser, [mail], async (err, results) => {
      if (err) {
        console.error("Database error during user check:", err);
        return res.status(500).send("Error checking user existence");
      }

      if (results.length > 0) {
        return res.status(400).send("Email already registered");
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const sql =
          "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
        db.query(sql, [username, mail, hashedPassword], (err, result) => {
          if (err) {
            console.error("Database error during signup:", err);
            return res.status(500).send("Error during signup");
          }

          req.session.userId = result.insertId;
          req.session.username = username;

          res.redirect("/home");
        });
      } catch (hashError) {
        console.error("Password hashing error:", hashError);
        res.status(500).send("Error during signup");
      }
    });
  } catch (error) {
    console.error("General signup error:", error);
    res.status(500).send("Error during signup");
  }
});

app.post("/login", (req, res) => {
  console.log("Login request body:", {
    mail: req.body.mail,
    passwordReceived: !!req.body.password,
  });

  const { mail, password } = req.body;

  if (!mail || !password) {
    return res.status(400).send("All fields are required");
  }

  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [mail], async (err, results) => {
    if (err) {
      console.error("Database error during login:", err);
      return res.status(500).send("Error during login");
    }

    if (results.length === 0) {
      return res.status(401).send("Invalid email or password");
    }

    const user = results[0];

    try {
      if (user.password === password) {
        req.session.userId = user.id;
        req.session.username = user.username;
        return res.redirect("/home");
      } else {
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (passwordMatch) {
          req.session.userId = user.id;
          req.session.username = user.username;
          return res.redirect("/home");
        } else {
          return res.status(401).send("Invalid email or password");
        }
      }
    } catch (error) {
      console.error("Password comparison error:", error);
      return res.status(500).send("Error during login");
    }
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Error during logout");
    }
    res.redirect("/login");
  });
});

const requireLogin = (req, res, next) => {
  if (!req.session.userId) {
    return res.redirect("/login");
  }
  next();
};

app.get("/home", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "home.html"));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/get-username", (req, res) => {
  console.log("Session data:", req.session);
  if (req.session && req.session.username) {
    res.json({ username: req.session.username });
  } else {
    res.json({ username: null });
  }
});

app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, "signup.html"));
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Something broke!");
});

app.post("/submit-blog", requireLogin, (req, res) => {
  console.log("=== Blog Submission Attempt ===");
  console.log("Session data:", req.session);
  console.log("User ID:", req.session.userId);
  console.log("Request body:", req.body);

  const { title, content } = req.body;
  const userId = req.session.userId;

  if (!title || !content) {
    console.log("Validation failed: missing title or content");
    return res.status(400).json({ error: "Title and content are required" });
  }

  if (!userId) {
    console.log("Validation failed: no userId in session");
    return res.status(401).json({ error: "User not authenticated" });
  }

  const sql =
    "INSERT INTO blog_posts (user_id, title, content) VALUES (?, ?, ?)";
  console.log("Executing SQL:", sql);
  console.log("Parameters:", [userId, title, content]);

  db.query(sql, [userId, title, content], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Error submitting blog post" });
    }
    console.log("Database insert successful:", result);
    res.status(201).json({
      message: "Blog post submitted successfully",
      id: result.insertId,
    });
  });
});

app.get("/api/blog-posts", (req, res) => {
  const sql = `
        SELECT 
            blog_posts.id,
            blog_posts.title,
            blog_posts.content,
            blog_posts.created_at,
            users.username
        FROM blog_posts
        JOIN users ON blog_posts.user_id = users.id
        ORDER BY blog_posts.created_at DESC
    `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching blog posts:", err);
      return res.status(500).json({ error: "Error fetching blog posts" });
    }
    res.json(results);
  });
});

app.get("/blogs", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "blogs.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
