const jwt = require('jsonwebtoken');
const AppError = require('../utils/AppError');

const isAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next(new AppError('No autorizado. Token faltante o formato incorrecto.', 401));
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.usuario = decoded; // Guardamos los datos del usuario para usarlos en la ruta
    next();
  } catch (error) {
    return next(new AppError('Token inválido o ha expirado.', 401));
  }
};

module.exports = isAuth;