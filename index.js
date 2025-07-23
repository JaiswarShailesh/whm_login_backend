const express = require("express");
const bcrypt = require("bcrypt");
const axios = require("axios");
const https = require("https");
const pool = require("./db");
const fs = require("fs");
const path = require("path");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(helmet());

const writeLogFile = (username, status) => {
  const logDir = path.join(__dirname, "logs");
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir);
  }

  const logPath = path.join(logDir, "login.log");

  const timestamp = new Date().toLocaleString("en-IN", {
    timeZone: "Asia/Kolkata",
    hour12: true,
  });

  const logEntry = `[${timestamp}] LOGIN ATTEMPT | Username: ${username} | Status: ${status}\n`;
  fs.appendFileSync(logPath, logEntry, "utf8");
};

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: {
    success: false,
    message: "Too many login attempts. Try again later.",
  },
});

app.post("/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  try {
    const [rows] = await pool.query("SELECT * FROM users WHERE username = ?", [
      username,
    ]);

    const user = rows[0];

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password are required",
      });
    }

    if (!user) {
      await pool.query(
        "INSERT INTO login_logs (username, time, status) VALUES (?, NOW(), ?)",
        [username, "FAILED"]
      );
      writeLogFile(username, "FAILED");

      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    const status = isMatch ? "SUCCESS" : "FAILED";

    await pool.query(
      "INSERT INTO login_logs (username, time, status) VALUES (?, NOW(), ?)",
      [username, status]
    );
    writeLogFile(username, status);

    const redirectURL = await getRedirectURL();

    if (isMatch) {
      return res.json({
        success: true,
        redirectUrl: redirectURL,
      });
    } else {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    }
  } catch (err) {
    console.error("🔥 Error during login:", err); // 👈 Add this to see error in console
    res.status(500).json({ success: false, message: "Server error" });
  }
});

const getRedirectURL = async () => {
  try {
    const apiUrl = `https://${process.env.WHM_IP}:2087/json-api/create_user_session?api.version=1&user=${process.env.WHM_USER}&service=whostmgrd`;

    const response = await axios.get(apiUrl, {
      headers: {
        Authorization: `whm ${process.env.WHM_USER}:${process.env.WHM_API_TOKEN}`,
      },
      httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    });

    const whmLoginUrl = response.data?.data?.url;

    if (!whmLoginUrl) {
      throw new Error("Login URL not found in WHM response.");
    }

    return whmLoginUrl;
  } catch (err) {
    console.error("Error:", err.response?.data || err.message);
    res.status(500).send("Failed to create WHM session.");
  }
};

app.listen(process.env.PORT || 5000, () => {
  console.log(`Server running...`);
});
