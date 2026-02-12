# app/error_handlers.py
import traceback
import logging
from flask import jsonify, request

logger = logging.getLogger(__name__)

def register_error_handlers(app):
    """Register all error handlers for the application"""
    
    # Custom application error
    class AppError(Exception):
        def __init__(self, message, status_code=400, payload=None):
            super().__init__()
            self.message = message
            self.status_code = status_code
            self.payload = payload
    
    app.AppError = AppError
    
    @app.errorhandler(400)
    def bad_request(e):
        logger.warning(f"Bad request: {str(e)} - Path: {request.path}")
        return jsonify({
            "error": "Bad request",
            "message": "The request could not be understood or was missing required parameters.",
            "path": request.path
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(e):
        logger.warning(f"Unauthorized: {str(e)} - Path: {request.path}")
        return jsonify({
            "error": "Unauthorized",
            "message": "Authentication is required and has failed or has not been provided.",
            "path": request.path
        }), 401
    
    @app.errorhandler(403)
    def forbidden(e):
        logger.warning(f"Forbidden: {str(e)} - Path: {request.path}")
        return jsonify({
            "error": "Forbidden",
            "message": "You don't have permission to access this resource.",
            "path": request.path
        }), 403
    
    @app.errorhandler(404)
    def not_found(e):
        logger.info(f"Not found: {request.path}")
        return jsonify({
            "error": "Not found",
            "message": "The requested resource was not found on the server.",
            "path": request.path
        }), 404
    
    @app.errorhandler(405)
    def method_not_allowed(e):
        logger.warning(f"Method not allowed: {request.method} {request.path}")
        return jsonify({
            "error": "Method not allowed",
            "message": f"The {request.method} method is not supported for this endpoint.",
            "path": request.path
        }), 405
    
    @app.errorhandler(409)
    def conflict(e):
        logger.warning(f"Conflict: {str(e)} - Path: {request.path}")
        return jsonify({
            "error": "Conflict",
            "message": "The request could not be completed due to a conflict with the current state of the resource.",
            "path": request.path
        }), 409
    
    @app.errorhandler(422)
    def unprocessable_entity(e):
        logger.warning(f"Unprocessable entity: {str(e)} - Path: {request.path}")
        return jsonify({
            "error": "Unprocessable entity",
            "message": "The request was well-formed but could not be processed due to semantic errors.",
            "path": request.path
        }), 422
    
    @app.errorhandler(429)
    def too_many_requests(e):
        logger.warning(f"Too many requests: {str(e)} - Path: {request.path}")
        return jsonify({
            "error": "Too many requests",
            "message": "Rate limit exceeded. Please try again later.",
            "path": request.path
        }), 429
    
    @app.errorhandler(500)
    def server_error(e):
        logger.error(f"Server error: {str(e)} - Path: {request.path}")
        if app.config.get('DEBUG', False):
            logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            "error": "Server error",
            "message": "An internal server error occurred. Please try again later.",
            "path": request.path
        }), 500
    
    @app.errorhandler(AppError)
    def handle_app_error(error):
        response = jsonify({
            "error": error.__class__.__name__,
            "message": error.message,
            "path": request.path,
            **(error.payload or {})
        })
        response.status_code = error.status_code
        return response