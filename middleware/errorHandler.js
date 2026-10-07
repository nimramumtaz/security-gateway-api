class ApiError extends Error {
  constructor(statusCode, errorCode, message) {
    super(message);
    this.statusCode = statusCode;
    this.errorCode = errorCode;
  }
}

function notFoundHandler(req, res, next) {
  next(new ApiError(404, "ROUTE_NOT_FOUND", `Route ${req.method} ${req.originalUrl} does not exist`));
}

// Must be the LAST middleware registered in server.js
function errorHandler(err, req, res, next) {
  const statusCode = err.statusCode || 500;
  const errorCode = err.errorCode || "INTERNAL_SERVER_ERROR";

  res.status(statusCode).json({
    error_code: errorCode,
    message: err.message || "Something went wrong",
    timestamp: new Date().toISOString(),
  });
}

module.exports = { ApiError, notFoundHandler, errorHandler };
