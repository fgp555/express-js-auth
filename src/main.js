const express = require("express");
const morgan = require("morgan");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(morgan("dev"));
app.use(express.json());

const JWT_SECRET = "JWT_SECRET";
const JWT_REFRESH_SECRET = "REFRESH_SECRET";
const EXPIRES_IN = "1h";
const REFRESH_EXPIRES_IN = "3d";

// 📦 Usuarios (con _id como string)
const users = [
  { _id: "1", name: "Admin User", email: "admin@gmail.com", password: "admin@gmail.com", role: "admin" },
  { _id: "2", name: "Regular User", email: "user@gmail.com", password: "user@gmail.com", role: "user" },
];

let refreshTokens = [];

// 🔐 Tokens
function generateAccessToken(user) {
  return jwt.sign({ _id: user._id, role: user.role }, JWT_SECRET, { expiresIn: EXPIRES_IN });
}

function generateRefreshToken(user) {
  const refreshToken = jwt.sign({ _id: user._id, role: user.role }, JWT_REFRESH_SECRET, {
    expiresIn: REFRESH_EXPIRES_IN,
  });
  refreshTokens.push(refreshToken);
  return refreshToken;
}

// 🔒 Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ success: false, message: "Missing token" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: "Invalid token" });
    req.user = user;
    next();
  });
}

// ✅ Home
app.get("/", (req, res) => res.send("✅ Server running!"));

// 🔑 Login
app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ success: false, message: "Invalid credentials" });

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  res.json({
    success: true,
    message: "Login successful",
    accessToken,
    refreshToken,
    user: {
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
  });
});

// 🔁 Refresh token
app.post("/api/auth/refresh-token", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken || !refreshTokens.includes(refreshToken)) {
    return res.status(403).json({ success: false, message: "Invalid refresh token" });
  }

  jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: "Token expired" });

    const accessToken = generateAccessToken({ _id: user._id, role: user.role });
    res.json({ success: true, accessToken, expiresIn: EXPIRES_IN });
  });
});

// 🔒 Logout
app.post("/api/auth/logout", (req, res) => {
  const { refreshToken } = req.body;
  jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err) => {
    if (err) return res.status(403).json({ success: false, message: "Invalid refresh token" });

    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
    return res.json({ success: true, message: "Logged out successfully" });
  });
});

// 📋 Obtener usuarios
app.get("/api/users/findAll", authenticateToken, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + limit;

  const sanitizedUsers = users.map(({ password, ...rest }) => rest);

  const paginatedResults = sanitizedUsers.slice(startIndex, endIndex);
  const totalItems = sanitizedUsers.length;
  const totalPages = Math.ceil(totalItems / limit);
  const hasMore = page < totalPages;

  res.json({
    page,
    totalPages,
    totalItems,
    hasMore,
    results: paginatedResults,
  });
});

// 📌 Obtener perfil actual
app.get("/api/auth/me", authenticateToken, (req, res) => {
  const user = users.find((u) => u._id === req.user._id);
  if (!user) return res.status(404).json({ success: false, message: "User not found" });

  const { password, ...safeUser } = user;
  res.json({ success: true, user: safeUser });
});

// 📝 Registro
app.post("/api/auth/register", (req, res) => {
  const { name, email, password, role = "user" } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  const exists = users.find((u) => u.email === email);
  if (exists) return res.status(409).json({ success: false, message: "Email already exists" });

  const newUser = {
    _id: (users.length + 1).toString(),
    name,
    email,
    password,
    role,
  };

  users.push(newUser);

  const accessToken = generateAccessToken(newUser);
  const refreshToken = generateRefreshToken(newUser);

  res.status(201).json({
    success: true,
    message: "User registered",
    accessToken,
    refreshToken,
    user: {
      _id: newUser._id,
      name: newUser.name,
      email: newUser.email,
      role: newUser.role,
    },
  });
});

// 🔍 Decodificar token
app.post("/api/auth/decode-token", (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(400).json({
      success: false,
      message: "Token is required in request body",
    });
  }

  try {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) {
      return res.status(400).json({
        success: false,
        message: "Invalid token",
      });
    }

    const { payload } = decoded;
    const payloadHumanReadable = {
      ...payload,
      iat___human: payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
      exp___human: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
      currentTime: new Date().toISOString(),
    };

    res.json({
      success: true,
      decoded: {
        ...decoded,
        payloadHumanReadable,
      },
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "Failed to decode token",
      error: error.message,
    });
  }
});

// ❌ Eliminar usuario
app.delete("/api/users/remove/:id", authenticateToken, (req, res) => {
  const requestingUser = users.find((u) => u._id === req.user._id);
  if (!requestingUser) {
    return res.status(401).json({ success: false, message: "Authenticated user not found" });
  }

  if (requestingUser.role !== "admin") {
    return res.status(403).json({ success: false, message: "Only admins can delete users" });
  }

  const userId = req.params.id; // 👈 ahora es string
  const index = users.findIndex((u) => u._id === userId);
  if (index === -1) return res.status(404).json({ success: false, message: "User not found" });

  const deletedUser = users.splice(index, 1)[0];
  const { password, ...safeDeleted } = deletedUser;
  res.json({
    success: true,
    message: "User deleted",
    user: safeDeleted,
  });
});

app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
