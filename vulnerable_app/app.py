from flask import Flask, request, jsonify
import sqlite3
import subprocess
import os
import yaml

app = Flask(__name__)

# Hardcoded AWS Credentials (A02: Cryptographic Failures / A05: Security Misconfiguration)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def get_db_connection():
    conn = sqlite3.connect('juice_shop.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/api/users/login', methods=['POST'])
def login():
    """A03: Injection - SQL Injection vulnerability"""
    email = request.form.get('email')
    password = request.form.get('password')
    
    conn = get_db_connection()
    # Extremely vulnerable SQL query
    query = f"SELECT * FROM users WHERE email = '{email}' AND password = '{password}'"
    user = conn.execute(query).fetchone()
    conn.close()
    
    if user:
        return jsonify({"status": "success", "token": "admin-token-12345"})
    return jsonify({"status": "error"}), 401

@app.route('/api/system/ping', methods=['GET'])
def ping():
    """A03: Injection - OS Command Injection vulnerability"""
    target = request.args.get('target', '8.8.8.8')
    # Extremely vulnerable OS command injection
    result = subprocess.check_output(f"ping -c 1 {target}", shell=True)
    return result

@app.route('/api/config/load', methods=['POST'])
def load_config():
    """A08: Software and Data Integrity Failures - Insecure Deserialization"""
    yaml_data = request.data
    # Extremely vulnerable YAML deserialization
    config = yaml.load(yaml_data, Loader=yaml.Loader)
    return jsonify(config)

@app.route('/api/files', methods=['GET'])
def read_file():
    """A01: Broken Access Control - Path Traversal"""
    filename = request.args.get('file')
    # Vulnerable to path traversal (e.g. ?file=../../../../etc/passwd)
    with open(f"/var/www/html/{filename}", 'r') as f:
        return f.read()

if __name__ == '__main__':
    # A05: Security Misconfiguration - Running in debug mode
    app.run(host='0.0.0.0', port=5000, debug=True)
