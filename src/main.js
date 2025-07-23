const express = require("express");
const morgan = require("morgan");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(morgan("dev"));
app.use(express.json());

const JWT_SECRET = "my_secret_access";
const JWT_REFRESH_SECRET = "my_secret_refresh";
const EXPIRES_IN = "15m";
const REFRESH_EXPIRES_IN = "7d";

const users = [
  { id: 1, name: "Admin User", email: "admin@example.com", password: "123456", role: "admin" },
  { id: 2, name: "Regular User", email: "user@example.com", password: "abcdef", role: "user" },
];

// 🛡️ Lista temporal de refreshTokens
let refreshTokens = [];

// 🛠 Función para generar tokens
function generateAccessToken(user) {
  return jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: EXPIRES_IN });
}

function generateRefreshToken(user) {
  const refreshToken = jwt.sign({ id: user.id }, JWT_REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES_IN });
  refreshTokens.push(refreshToken);
  return refreshToken;
}

// 🔐 Middleware
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

// 🏁 Ruta base
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
    user: { id: user.id, name: user.name, email: user.email, role: user.role },
  });
});

// 🔁 Refresh Token
app.post("/api/auth/refresh-token", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken || !refreshTokens.includes(refreshToken)) {
    return res.status(403).json({ success: false, message: "Invalid refresh token" });
  }

  jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: "Token expired" });

    const accessToken = generateAccessToken({ id: user.id, role: user.role });
    res.json({ success: true, accessToken });
  });
});

// 🔒 Logout (opcional)
app.post("/api/auth/logout", (req, res) => {
  const { refreshToken } = req.body;
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
  res.json({ success: true, message: "Logged out successfully" });
});

// 📋 Usuarios (protegido)
app.get("/api/users", authenticateToken, (req, res) => {
  const sanitizedUsers = users.map(({ password, ...u }) => u);
  res.json({ success: true, users: sanitizedUsers });
});

// 📝 Registro
app.post("/api/auth/register", (req, res) => {
  const { name, email, password, role = "user" } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  const exists = users.find((u) => u.email === email);
  if (exists) return res.status(409).json({ success: false, message: "Email already exists" });

  const newUser = { id: users.length + 1, name, email, password, role };
  users.push(newUser);

  const accessToken = generateAccessToken(newUser);
  const refreshToken = generateRefreshToken(newUser);

  res.status(201).json({
    success: true,
    message: "User registered",
    accessToken,
    refreshToken,
    user: { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role },
  });
});

// 📦 Decodificar un JWT y mostrar iat/exp legibles
app.post("/api/auth/decode", (req, res) => {
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

    // Convertir iat y exp a formato humano (si existen)
    const { payload } = decoded;
    const payloadHumanReadable = {
      ...payload,
      iat_human: payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
      exp_human: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
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
app.delete("/api/users/:id", authenticateToken, (req, res) => {
  const userId = parseInt(req.params.id);
  const index = users.findIndex((u) => u.id === userId);
  if (index === -1) return res.status(404).json({ success: false, message: "User not found" });

  const deletedUser = users.splice(index, 1)[0];
  res.json({
    success: true,
    message: "User deleted",
    user: { id: deletedUser.id, name: deletedUser.name, email: deletedUser.email, role: deletedUser.role },
  });
});

app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
