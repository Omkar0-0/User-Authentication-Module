# User Authentication Module

Programming language: Python

Frameworks: Flask, Flask-SQLAlchemy

Database: SQLite (file-based `app.db`)


Notes on security

- Passwords are hashed with Werkzeug `generate_password_hash`.
