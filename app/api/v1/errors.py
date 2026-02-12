from flask import jsonify
from werkzeug.exceptions import HTTPException
import traceback
import logging

def register_error_handlers(app):
    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        """
        Handles known HTTP errors (404, 401, 403, etc.)
        """
        response = {
            "error": e.name,
            "message": e.description,
            "status_code": e.code,
        }
        return jsonify(response), e.code

    @app.errorhandler(Exception)
    def handle_exception(e):
        """
        Handles all unexpected server errors
        Prevents stack trace leakage in production
        """
        logging.error("Unhandled Exception:")
        logging.error(traceback.format_exc())

        response = {
            "error": "Internal Server Error",
            "message": "Something went wrong. Please try again later.",
            "status_code": 500,
        }
        return jsonify(response), 500
