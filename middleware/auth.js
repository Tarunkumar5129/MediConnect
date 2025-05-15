// middleware/auth.js

const jwt = require("jsonwebtoken");

module.exports = function auth(req, res, next) {
  try {
    
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ message: "No token provided" });
    }
    const parts = authHeader.split(" ");
    if (parts.length !== 2 || parts[0] !== "Bearer") {
      return res.status(401).json({ message: "Token error" });
    }

    const token = parts[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: "Invalid token" });
      }
      req.user = decoded;
      next();
    });
  } catch (err) {
    console.error("Auth middleware error:", err);
    res.status(500).json({ message: "Server error in auth" });
  }
};
