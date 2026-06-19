module.exports = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  if (process.env.NODE_ENV === 'development') {
    res.status(err.statusCode).json({ status: 'error', message: err.message, stack: err.stack });
  } else {
    res.status(err.statusCode).json({ status: 'error', message: err.isOperational ? err.message : 'Error interno del servidor' });
  }
};