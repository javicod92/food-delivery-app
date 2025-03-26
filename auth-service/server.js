import dotenv from "dotenv";
dotenv.config();
import express, { json } from "express";
import { hash, compare } from "bcryptjs";
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
const app = express();
app.use(json());

// Registro de usuarios
app.post("/register", async (req, res) => {
  const { email, password, role } = req.body;
  const hashedPassword = await hash(password, 10);
  const user = await prisma.user.create({
    data: { email, password: hashedPassword, role },
  });
  res.json(user);
});

// Login y generación de token
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !(await compare(password, user.password))) {
    return res.status(401).json({ error: "Credenciales inválidas" });
  }
  const token = jwt.sign(
    { userId: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
  res.json({ token });
});

// Proteger rutas con autenticación
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Acceso denegado" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: "Token inválido" });
  }
};

// Ruta protegida de prueba
app.get("/profile", authMiddleware, async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.user.userId } });
  res.json(user);
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Auth service running on port ${PORT}`));
