require('dotenv').config();
const express = require('express');

// Importaciones para el adaptador de Prisma 7
const { Pool } = require('pg');
const { PrismaPg } = require('@prisma/adapter-pg');
const { PrismaClient } = require('@prisma/client');

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { z } = require('zod');

const AppError = require('./utils/AppError');
const globalErrorHandler = require('./middleware/errorMiddleware');
const isAuth = require('./middleware/isAuth');

const app = express();
app.use(express.json());

// Inicialización de Prisma con el adaptador de Postgres
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

// --- ESQUEMA DE VALIDACION (ZOD) ---
const AuthSchema = z.object({
  email: z.string({
    required_error: "El email es obligatorio",
    invalid_type_error: "El email debe ser un texto"
  }).email("Formato de correo inválido"),
  
  password: z.string({
    required_error: "La contraseña es obligatoria",
    invalid_type_error: "La contraseña debe ser un texto"
  }).min(6, "La contraseña debe tener al menos 6 caracteres")
}).strict();

// --- 1. ENDPOINT: REGISTRO ---
app.post('/registro', async (req, res, next) => {
  try {
    // Validación estricta de datos entrantes
    const { email, password } = AuthSchema.parse(req.body);

    // Encriptar la contraseña (10 saltos es el estándar)
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Guardar usuario en la base de datos
    const nuevoUsuario = await prisma.usuario.create({
      data: { 
        email: email, 
        password: hashedPassword 
      }
    });

    res.status(201).json({ 
      mensaje: 'Usuario registrado exitosamente', 
      id: nuevoUsuario.id 
    });
  } catch (error) {
    // Captura de errores de Zod
    if (error instanceof z.ZodError) {
      const mensaje = error.issues.map(e => e.message).join(' | ');
      return next(new AppError(mensaje, 400));
    }
    // Captura de error de Prisma (P2002 = Violación de restricción única / Email ya existe)
    if (error.code === 'P2002') {
      return next(new AppError('El email ya está registrado', 400));
    }
    next(error); // Pasa cualquier otro error al middleware global
  }
});

// --- 2. ENDPOINT: LOGIN ---
app.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return next(new AppError('Email y password son obligatorios', 400));
    }

    // Buscar el usuario por correo
    const usuario = await prisma.usuario.findUnique({ where: { email } });
    if (!usuario) {
      return next(new AppError('Credenciales inválidas', 401));
    }

    // Validar que la contraseña coincida con el hash almacenado
    const passwordValido = await bcrypt.compare(password, usuario.password);
    if (!passwordValido) {
      return next(new AppError('Credenciales inválidas', 401));
    }

    // Generar JSON Web Token (Expira en 1 hora)
    const token = jwt.sign(
      { id: usuario.id, email: usuario.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(200).json({ 
      mensaje: 'Login exitoso', 
      token 
    });
  } catch (error) {
    next(error);
  }
});

// --- 3. ENDPOINT PROTEGIDO ---
// Se inyecta el middleware isAuth antes de ejecutar la lógica de la ruta
app.get('/ruta-privada', isAuth, async (req, res, next) => {
  res.status(200).json({
    mensaje: '¡Acceso concedido! Tienes un token válido.',
    datosDelUsuario: req.usuario 
  });
});

// --- MIDDLEWARE DE ERRORES ---
// Debe ir SIEMPRE al final de todas las rutas
app.use(globalErrorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
});