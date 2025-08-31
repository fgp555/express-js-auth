// 🔧 Configuración inicial

require("dotenv").config();
const express = require("express");
const morgan = require("morgan");
const cors = require("cors");
const session = require("express-session");
const passport = require("passport");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;

// 🔐 Variables de entorno
const JWT_SECRET = process.env.JWT_SECRET || "secret";
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "refresh-secret";
const EXPIRES_IN = "3d";
const REFRESH_EXPIRES_IN = "7d";

// 🔍 Variables de Google OAuth
const GOOGLE_OAUTH_ENABLED = process.env.GOOGLE_OAUTH_ENABLED === "true";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || "http://localhost:3000/api/oauth/callback";
const GOOGLE_CLIENT_URL = process.env.GOOGLE_CLIENT_URL;

// 🧩 Middlewares
app.use(morgan("dev"));
app.use(cors());
app.use(express.json());
app.use(express.static("public")); // para servir index.html

// 🔐 Configurar Passport solo si Google OAuth está habilitado
if (GOOGLE_OAUTH_ENABLED) {
  console.log("🔐 Google OAuth is ENABLED");

  // Validar que las credenciales de Google estén configuradas
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    console.error("❌ Google OAuth is enabled but GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET are missing!");
    process.exit(1);
  }

  const GoogleStrategy = require("passport-google-oauth20").Strategy;

  app.use(
    session({
      secret: process.env.SESSION_SECRET || "session-secret",
      resave: false,
      saveUninitialized: false,
    })
  );
  app.use(passport.initialize());
  app.use(passport.session());

  // Configurar serialización de Passport
  passport.serializeUser((user, done) => done(null, user));
  passport.deserializeUser((obj, done) => done(null, obj));

  // Configurar Google Strategy
  passport.use(
    new GoogleStrategy(
      {
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: GOOGLE_CALLBACK_URL,
      },
      (accessToken, refreshToken, profile, done) => {
        const user = {
          _id: profile.id,
          name: profile.displayName,
          email: profile.emails?.[0]?.value || "",
          role: "user",
        };
        return done(null, user);
      }
    )
  );
} else {
  console.log("🔒 Google OAuth is DISABLED");
}

// 🧍 Usuarios simulados
const users = [
  {
    _id: "1",
    name: "Admin User",
    username: "admin",
    email: "admin@gmail.com",
    password: "admin@gmail.com",
    role: "admin",
  },
  {
    _id: "2",
    name: "Regular User",
    username: "user",
    email: "user@gmail.com",
    password: "user@gmail.com",
    role: "user",
  },
];

let refreshTokens = [];

// 🔐 Funciones JWT
function generateAccessToken(user) {
  return jwt.sign({ _id: user._id, role: user.role, email: user.email, name: user.name, sub: user._id }, JWT_SECRET, {
    expiresIn: EXPIRES_IN,
  });
}

function generateRefreshToken(user) {
  const refreshToken = jwt.sign({ _id: user._id, role: user.role }, JWT_REFRESH_SECRET, {
    expiresIn: REFRESH_EXPIRES_IN,
  });
  refreshTokens.push(refreshToken);
  return refreshToken;
}

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
app.get("/hello", (req, res) => res.send("✅ Server running!"));

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
  const refreshToken = req.body.refreshToken;

  if (!refreshToken) {
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
  const refreshToken = req.body.refreshToken;
  if (!refreshToken) {
    return res.status(403).json({ success: false, message: "Invalid refresh token" });
  }

  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

  res.json({ success: true, message: "Logged out successfully" });
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

  const userId = req.params.id;
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

// 🔍 Verificar existencia de email/username
app.get("/api/auth/check-existence", (req, res) => {
  const { email, username } = req.query;

  if (!email && !username) {
    return res.status(400).json({
      success: false,
      message: "You must provide either email or username to check.",
    });
  }

  const emailExists = email ? users.some((u) => u.email === email) : false;
  const usernameExists = username ? users.some((u) => u.username === username) : false;

  res.json({
    success: true,
    emailExists,
    usernameExists,
  });
});

// 📊 Endpoint para obtener información del servidor
app.get("/api/server/info", (req, res) => {
  res.json({
    success: true,
    server: {
      oauth: {
        googleEnabled: GOOGLE_OAUTH_ENABLED,
      },
      endpoints: {
        auth: ["/api/auth/login", "/api/auth/register", "/api/auth/logout"],
        ...(GOOGLE_OAUTH_ENABLED && {
          oauth: ["/api/oauth/login", "/api/oauth/callback"],
        }),
        users: ["/api/users/findAll", "/api/users/remove/:id"],
        utils: ["/api/auth/decode-token", "/api/auth/check-existence"],
      },
    },
  });
});

// 🔐 Google OAuth Routes (solo si está habilitado)
if (GOOGLE_OAUTH_ENABLED) {
  // Google OAuth login
  app.get("/api/oauth/login", passport.authenticate("google", { scope: ["profile", "email"] }));

  // Google OAuth callback
  app.get("/api/oauth/callback", passport.authenticate("google", { failureRedirect: "/index.html" }), (req, res) => {
    const user = req.user;
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    if (GOOGLE_CLIENT_URL) {
      res.redirect(GOOGLE_CLIENT_URL + `/auth/login-google?accessToken=${accessToken}&refreshToken=${refreshToken}`);
    } else {
      res.redirect(`/index.html?accessToken=${accessToken}`);
    }
  });
} else {
  // Rutas de fallback cuando Google OAuth está deshabilitado
  app.get("/api/oauth/login", (req, res) => {
    res.status(503).json({
      success: false,
      message: "Google OAuth is disabled. Enable it by setting GOOGLE_OAUTH_ENABLED=true in your .env file",
    });
  });

  app.get("/api/oauth/callback", (req, res) => {
    res.status(503).json({
      success: false,
      message: "Google OAuth is disabled. Enable it by setting GOOGLE_OAUTH_ENABLED=true in your .env file",
    });
  });
}

// 🚀 Iniciar servidor
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`🔐 Google OAuth: ${GOOGLE_OAUTH_ENABLED ? "ENABLED" : "DISABLED"}`);
  if (GOOGLE_OAUTH_ENABLED) {
    console.log(`📍 Google OAuth Login: http://localhost:${PORT}/api/oauth/login`);
    console.log(`📍 Google OAuth Callback: ${GOOGLE_CALLBACK_URL}`);
  }
});
