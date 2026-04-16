"""
SAST test file — intentionally contains code-level vulnerabilities detectable by Snyk Code.
For security testing purposes only.
"""

import os
import subprocess
import sqlite3
import pickle
import hashlib
import random
import requests
from flask import Flask, request


app = Flask(__name__)

DB = "users.db"
SECRET_KEY = "hardcoded_secret_1234!"  # noqa: S105 — hardcoded credential


# SQL Injection — user input concatenated directly into query
def get_user(username):
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


# Command Injection — user input passed to shell
def ping_host(host):
    result = subprocess.check_output("ping -c 1 " + host, shell=True)
    return result


# Path Traversal — user-controlled path used in file open
def read_file(filename):
    with open("/var/data/" + filename, "r") as f:
        return f.read()


# Insecure Deserialization — pickle.loads on untrusted data
def load_session(session_bytes):
    return pickle.loads(session_bytes)


# Weak Hashing — MD5 used for password storage
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


# Insecure Randomness — random used instead of secrets for token generation
def generate_token():
    return str(random.randint(100000, 999999))


# SSRF — user-controlled URL fetched server-side without validation
@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    response = requests.get(url)
    return response.text


# XSS — user input returned in HTML response without escaping
@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    return "<h1>Hello, " + name + "</h1>"


# Open Redirect — user-controlled redirect target
@app.route("/redirect")
def redirect_user():
    target = request.args.get("next", "/")
    return app.make_response(("", 302, {"Location": target}))


if __name__ == "__main__":
    app.run(debug=True)
