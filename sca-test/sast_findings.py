"""
SAST test file — intentionally contains code-level vulnerabilities detectable by Snyk Code.
For security testing purposes only.
"""

import ipaddress
import os
import subprocess
import sqlite3
import pickle
import hashlib
import random
import socket
from urllib.parse import urlparse

import requests
from flask import Flask, request, abort


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


ALLOWED_FETCH_SCHEMES = {"http", "https"}

@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    if not url:
        abort(400, "Missing url parameter")

    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_FETCH_SCHEMES:
        abort(400, "Scheme not allowed")

    hostname = parsed.hostname
    if not hostname:
        abort(400, "Invalid URL")

    try:
        resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        abort(400, "Cannot resolve hostname")

    for family, _type, _proto, _canonname, sockaddr in resolved:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            abort(403, "Requests to private/internal addresses are not allowed")

    response = requests.get(url, allow_redirects=False, timeout=5)
    return response.text


# XSS — user input returned in HTML response without escaping
@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    return "<h1>Hello, " + name + "</h1>"



if __name__ == "__main__":
    app.run(debug=True)
