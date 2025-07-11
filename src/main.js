const express = require("express");
const morgan = require("morgan");
const cors = require("cors");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(morgan("dev"));
app.use(express.json());

// 🔐 Usuarios mock (con name, email, password, role)
const users = [
  { id: 1, name: "Admin User", email: "admin@example.com", password: "123456", role: "admin" },
  { id: 2, name: "Regular User", email: "user@example.com", password: "abcdef", role: "user" },
];

// 🎯 Token mock (como si fuera JWT)
const MOCK_TOKEN = "mocked.token.123456";

// 🔐 Middleware para proteger rutas
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token || token !== MOCK_TOKEN) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized: Invalid or missing token",
    });
  }
  next();
}

// ✅ Ruta base
app.get("/", (req, res) => res.send("✅ Server running!"));

// 📄 Obtener todos los usuarios (sin contraseñas)
app.get("/api/users", authenticateToken, (req, res) => {
  const sanitizedUsers = users.map(({ password, ...user }) => user);
  res.json({
    success: true,
    users: sanitizedUsers,
  });
});

// 🔐 Login
app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;

  const user = users.find((u) => u.email === email && u.password === password);
  if (user) {
    res.json({
      success: true,
      message: "Login successful",
      token: MOCK_TOKEN,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } else {
    res.status(401).json({
      success: false,
      message: "Invalid credentials",
    });
  }
});

// 📝 Registro
app.post("/api/auth/register", (req, res) => {
  const { name, email, password, role = "user" } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      success: false,
      message: "Name, email and password are required",
    });
  }

  const existingUser = users.find((u) => u.email === email);
  if (existingUser) {
    return res.status(409).json({
      success: false,
      message: "Email already exists",
    });
  }

  const newUser = {
    id: users.length + 1,
    name,
    email,
    password,
    role,
  };

  users.push(newUser);

  res.status(201).json({
    success: true,
    message: "User registered successfully",
    token: MOCK_TOKEN,
    user: {
      id: newUser.id,
      name: newUser.name,
      email: newUser.email,
      role: newUser.role,
    },
  });
});

// ❌ Eliminar usuario por ID
app.delete("/api/users/:id", authenticateToken, (req, res) => {
  const userId = parseInt(req.params.id);
  const index = users.findIndex((u) => u.id === userId);

  if (index === -1) {
    return res.status(404).json({
      success: false,
      message: "User not found",
    });
  }

  const deletedUser = users.splice(index, 1)[0];

  res.json({
    success: true,
    message: "User deleted successfully",
    user: {
      id: deletedUser.id,
      name: deletedUser.name,
      email: deletedUser.email,
      role: deletedUser.role,
    },
  });
});

app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
