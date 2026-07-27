require("dotenv").config();

const express = require("express");
const cors = require("cors");
const nodemailer = require("nodemailer");
const helmet = require("helmet");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const hpp = require("hpp");
const morgan = require("morgan");
const validator = require("validator");
const { Pool } = require("pg");

const app = express();

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));


/* =========================
   SECURITY
========================= */

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  cors({
    origin: [
      "https://7930navid.github.io",
      "http://localhost:8080",
					"https://users-server-xyvg.onrender.com"
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

app.use(hpp());
app.use(morgan("combined"));

/* =========================
   RATE LIMIT
========================= */

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200
  })
);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: {
    message: "Too many login attempts"
  }
});

/* =========================
   DATABASE (NEXTALK DB)
========================= */

const db = new Pool({
  connectionString: process.env.NEXTALK_DATABASE_URL || process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false
});

/* =========================
   EMAIL TRANSPORTER
========================= */

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

/* =========================
   VERIFY MAIL SERVER
========================= */

transporter.verify((error, success) => {
  if (error) {
    console.log("❌ Mail error:", error);
  } else {
    console.log("✅ NexTalk Mail server ready");
  }
});

/* =========================
   INIT DATABASE
========================= */

async function initDB() {
  await db.query(`
    CREATE EXTENSION IF NOT EXISTS pgcrypto;

    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      username TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT,
      bio TEXT DEFAULT '',
      avatar TEXT,
      cover_photo TEXT,
      reset_token TEXT,
      reset_expiry TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  console.log("✅ NexTalk Database ready");
}

/* =========================
   AUTH MIDDLEWARE
========================= */

function auth(req, res, next) {
  try {
    const header = req.headers.authorization;

    if (!header || !header.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "Unauthorized"
      });
    }

    const token = header.split(" ")[1];

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET,
      {
        issuer: "NexTalk",
        audience: "NexTalkUsers"
      }
    );

    req.user = decoded;

    next();

  } catch (err) {
    console.log(err);

    return res.status(403).json({
      message: "Invalid token"
    });
  }
}

/* =========================
   SIGNUP
========================= */

app.post("/signup", async (req, res) => {
  try {
    const {
      username,
      email,
      password,
      bio,
      avatar,
      cover_photo
    } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({
        message: "Missing fields"
      });
    }

    if (!validator.isEmail(email)) {
      return res.status(400).json({
        message: "Invalid email"
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        message: "Password must be at least 8 characters"
      });
    }

    const exists = await db.query(
      "SELECT id FROM users WHERE email=$1",
      [email]
    );

    if (exists.rows.length > 0) {
      return res.status(400).json({
        message: "User already exists"
      });
    }

    const hash = await bcrypt.hash(password, 12);

    await db.query(
      `
      INSERT INTO users
      (username,email,password,bio,avatar,cover_photo)
      VALUES ($1,$2,$3,$4,$5,$6)
      `,
      [
        username,
        email,
        hash,
        bio || "",
        avatar || "",
        cover_photo || ""
      ]
    );

    res.status(201).json({
      message: "User created successfully"
    });

  } catch (err) {
    console.log(err);

    res.status(500).json({
      message: "Server error"
    });
  }
});

/* =========================
   NORMAL SIGNIN
========================= */

app.post("/signin", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Missing fields"
      });
    }

    const result = await db.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        message: "Invalid credentials"
      });
    }

    const user = result.rows[0];

    if (!user.password) {
      return res.status(400).json({
        message: "You might have been logged in by using SSO before, so try the button ‘Continue with AsirNet’ to log in"
      });
    }

    const match = await bcrypt.compare(
      password,
      user.password
    );

    if (!match) {
      return res.status(401).json({
        message: "Invalid credentials"
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
        issuer: "NexTalk",
        audience: "NexTalkUsers"
      }
    );

    const {
      password: hiddenPassword,
      reset_token,
      reset_expiry,
      ...safeUser
    } = user;

    res.json({
      token,
      user: safeUser
    });

  } catch (err) {
    console.log(err);

    res.status(500).json({
      message: "Server error"
    });
  }
});

/* =========================
   SSO SIGNIN
========================= */

app.post("/sso-login", loginLimiter, async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        message: "SSO Token is required"
      });
    }

    // Decode SSO Token
    const decoded = jwt.verify(
      token,
      process.env.ASIRNET_SSO_SECRET || process.env.JWT_SECRET
    );

    // Check if user already exists
    let result = await db.query(
      "SELECT * FROM users WHERE email=$1",
      [decoded.email]
    );

    let user;

    if (result.rows.length === 0) {
      // Schema অনুযায়ী সব টেবিল কলাম ইনসার্ট করা হচ্ছে
      const newUser = await db.query(
        `
        INSERT INTO users (
          username, 
          email, 
          bio, 
          avatar, 
          cover_photo
        )
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        `,
        [
          decoded.username || decoded.name || decoded.email.split("@")[0],
          decoded.email,
          decoded.bio || "",
          decoded.avatar || decoded.profile_pic || "",
          decoded.cover_photo || decoded.coverPhoto || ""
        ]
      );
      user = newUser.rows[0];
    } else {
      user = result.rows[0];
    }

    // Generate NexTalk Session Token
    const sessionToken = jwt.sign(
      {
        id: user.id,
        email: user.email
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
        issuer: "NexTalk",
        audience: "NexTalkUsers"
      }
    );

    const {
      password: hiddenPassword,
      reset_token,
      reset_expiry,
      ...safeUser
    } = user;

    res.json({
      message: "SSO login successful",
      token: sessionToken,
      user: safeUser
    });

  } catch (err) {
    console.log("SSO Error:", err);

    res.status(401).json({
      message: "Invalid or expired SSO token"
    });
  }
});


/* =========================
   CURRENT USER
========================= */

app.get("/me", async (req, res) => {
  try {
    const email = req.query.email;
    let result;

    if (email) {
      // LOWER() ব্যবহার করার ফলে ছোট বা বড় হাতের অক্ষর থাকলেও সমস্যা হবে না
      result = await db.query(
        `SELECT id, username, email, bio, avatar, cover_photo
         FROM users
         WHERE LOWER(email) = LOWER($1)`,
        [email]
      );
    } else if (req.user && req.user.id) {
      result = await db.query(
        `SELECT id, username, email, bio, avatar, cover_photo
         FROM users
         WHERE id = $1`,
        [req.user.id]
      );
    } else {
      return res.status(400).json({ message: "User identity missing" });
    }

    // ইউজার না পাওয়া গেলে empty object না পাঠিয়ে ৪0৪ দিন
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    // সরাসরি অবজেক্ট পাঠাচ্ছে
    res.json(result.rows[0]);

  } catch (err) {
    console.error("Error in /me endpoint:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   UPDATE PROFILE
========================= */

app.put("/profile", async (req, res) => {
  try {
    const {
      username,
      bio,
      avatar,
      cover_photo
    } = req.body;

    const result = await db.query(
      `
      UPDATE users
      SET
      username=$1,
      bio=$2,
      avatar=$3,
      cover_photo=$4
      WHERE id=$5
      RETURNING
      id,
      username,
      email,
      bio,
      avatar,
      cover_photo
      `,
      [
        username,
        bio,
        avatar,
        cover_photo,
        req.user.id
      ]
    );

    res.json(result.rows[0]);

  } catch (err) {
    console.log(err);

    res.status(500).json({
      message: "Server error"
    });
  }
});

/* =========================
   ALL USERS
========================= */

app.get("/users", async (req, res) => {
  try {
    const result = await db.query(`
      SELECT
      id,
      username,
      email,
      bio,
      avatar,
      cover_photo
      FROM users
    `);

    res.json(result.rows);

  } catch (err) {
    console.log(err);

    res.status(500).json({
      message: "Server error"
    });
  }
});

/* =========================
   SEARCH USERS
========================= */

app.get("/search", async (req, res) => {
  try {
    const q = req.query.q || "";

    const result = await db.query(
      `
      SELECT
      id,
      username,
      email,
      bio,
      avatar,
      cover_photo
      FROM users
      WHERE
      username ILIKE $1
      OR
      email ILIKE $1
      `,
      [`%${q}%`]
    );

    res.json(result.rows);

  } catch (err) {
    console.log(err);

    res.status(500).json({
      message: "Server error"
    });
  }
});

/* =========================
   DELETE ACCOUNT
========================= */

app.delete("/delete-account", async (req, res) => {
  try {
    await db.query(
      "DELETE FROM users WHERE id=$1",
      [req.user.id]
    );

    res.json({
      message: "Account deleted"
    });

  } catch (err) {
    console.log(err);

    res.status(500).json({
      message: "Server error"
    });
  }
});

/* =========================
   FORGOT PASSWORD
========================= */

app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        message: "Email required"
      });
    }

    const user = await db.query(
      "SELECT id FROM users WHERE email=$1",
      [email]
    );

    if (user.rows.length === 0) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    const token = crypto
      .randomBytes(32)
      .toString("hex");

    const expiry = new Date(
      Date.now() + 15 * 60 * 1000
    );

    await db.query(
      `
      UPDATE users
      SET
      reset_token=$1,
      reset_expiry=$2
      WHERE email=$3
      `,
      [token, expiry, email]
    );

    const resetLink =
      `https://7930navid.github.io/My-platform/reset-password.html?token=${token}`;

    const mailOptions = {
      from: `"NexTalk Security" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Reset Your Password - NexTalk",

      html: `
      <div style="font-family:Poppins, sans-serif;padding:20px;">
        <h2>Reset Your Password</h2>

        <p>
          Click the button below to reset your NexTalk account password.
        </p>

        <a
          href="${resetLink}"
          style="
            display:inline-block;
            padding:14px 24px;
            background:#00e5ff;
            color:black;
            text-decoration:none;
            border-radius:10px;
            font-weight:bold;
          "
        >
          Reset Password
        </a>

        <p style="margin-top:20px;">
          This link expires in 15 minutes.
        </p>
      </div>
      `
    };

    try {
      await transporter.sendMail(mailOptions);

      return res.json({
        message: "Reset email sent"
      });

    } catch (mailError) {
      console.log(mailError);

      return res.status(500).json({
        message: "Email failed"
      });
    }

  } catch (err) {
    console.log(err);

    res.status(500).json({
      message: "Server error"
    });
  }
});

/* =========================
   RESET PASSWORD
========================= */

app.post("/reset-password", async (req, res) => {
  try {
    const {
      token,
      newPassword
    } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({
        message: "Missing fields"
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        message: "Password too short"
      });
    }

    const user = await db.query(
      `
      SELECT *
      FROM users
      WHERE
      reset_token=$1
      AND
      reset_expiry > NOW()
      `,
      [token]
    );

    if (user.rows.length === 0) {
      return res.status(400).json({
        message: "Invalid or expired token"
      });
    }

    const hash = await bcrypt.hash(
      newPassword,
      12
    );

    await db.query(
      `
      UPDATE users
      SET
      password=$1,
      reset_token=NULL,
      reset_expiry=NULL
      WHERE id=$2
      `,
      [
        hash,
        user.rows[0].id
      ]
    );

    res.json({
      message: "Password updated successfully"
    });

  } catch (err) {
    console.log(err);

    res.status(500).json({
      message: "Server error"
    });
  }
});

/* ============ FETCH ==============*/
app.get("/get/:name", (req, res) => {
  const name = req.params.name;
  const message = `${name} NexTalk server has been pinged`;
  res.send(message);
});

/* =========================
   SERVER START
========================= */

const PORT = process.env.PORT || 5000;

initDB().then(() => {
  app.listen(PORT, () => {
    console.log("🚀 NexTalk Server running on port", PORT);
  });
});
