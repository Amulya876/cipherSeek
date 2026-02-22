from flask import Flask, render_template, request, redirect, jsonify, session
from textblob import TextBlob
import bcrypt
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'privseek_secret_key_2026'

# SQLite Database Setup
DATABASE = 'privseek.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if users table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    users_exists = cursor.fetchone()
    
    # Check if uploads table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='uploads'")
    uploads_exists = cursor.fetchone()
    
    if not users_exists:
        # Create users table
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user'
            )
        ''')
        print("✅ Created users table")
    else:
        # Check if role column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        if 'role' not in columns:
            # Add role column to existing table
            cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
            print("✅ Added role column to users table")
    
    if not uploads_exists:
        # Create uploads table
        cursor.execute('''
            CREATE TABLE uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                description TEXT,
                is_encrypted INTEGER DEFAULT 0,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                file_size INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        print("✅ Created uploads table")
    
    conn.commit()
    conn.close()
    print("✅ SQLite Database Initialized Successfully!")

init_db()

@app.route("/")
def home():
    return render_template("login_choice.html")

@app.route("/register", methods=["POST"])
def register():
    name = request.form["name"]
    email = request.form["email"]
    password = request.form["password"]
    role = request.form.get("role", "user")  # Default role is 'user'

    conn = get_db()
    cursor = conn.cursor()

    # Check if user already exists
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        return "⚠ User already exists!"

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert user into database
    cursor.execute(
        "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
        (name, email, hashed_password, role)
    )
    conn.commit()
    conn.close()

    return redirect("/dashboard")


@app.route("/register-page")
def register_page():
    return render_template("login_choice.html")


@app.route("/user-login", methods=["GET", "POST"])
def user_login():
    if request.method == "GET":
        return render_template("user_login.html")
    
    email = request.form["email"]
    password = request.form["password"]

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ? AND role = 'user'", (email,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user["password"]):
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['name'] = user['name']
        session['role'] = 'user'
        return redirect("/dashboard")
    else:
        return "❌ Invalid User Credentials"


@app.route("/user-register", methods=["POST"])
def user_register():
    name = request.form["name"]
    email = request.form["email"]
    password = request.form["password"]

    conn = get_db()
    cursor = conn.cursor()

    # Check if user already exists
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        return "⚠ Email already exists!"

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert user into database with 'user' role
    cursor.execute(
        "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
        (name, email, hashed_password, 'user')
    )
    conn.commit()
    conn.close()

    return redirect("/user-login")


@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin_login.html")
    
    email = request.form["email"]
    password = request.form["password"]

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ? AND role = 'admin'", (email,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user["password"]):
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['name'] = user['name']
        session['role'] = 'admin'
        return redirect("/admin-dashboard")
    else:
        return "❌ Invalid Admin Credentials"


@app.route("/admin-register", methods=["POST"])
def admin_register():
    # Admin registration key for security (should be stored in environment variable)
    ADMIN_KEY = "admin123"  # Change this in production!
    
    name = request.form["name"]
    email = request.form["email"]
    password = request.form["password"]
    admin_key = request.form["admin_key"]

    # Verify admin key
    if admin_key != ADMIN_KEY:
        return "❌ Invalid Admin Registration Key"

    conn = get_db()
    cursor = conn.cursor()

    # Check if user already exists
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        return "⚠ Email already exists!"

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert admin into database with 'admin' role
    cursor.execute(
        "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
        (name, email, hashed_password, 'admin')
    )
    conn.commit()
    conn.close()

    return redirect("/admin-login")


# ----------------------------
# 🔹 LOGIN (Legacy - Redirect to appropriate page)
# ----------------------------
@app.route("/login", methods=["POST"])
def login():
    email = request.form["email"]
    password = request.form["password"]

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user["password"]):
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['name'] = user['name']
        session['role'] = user['role']
        
        # Redirect to admin or user dashboard based on role
        if user['role'] == 'admin':
            return redirect("/admin-dashboard")
        else:
            return redirect("/dashboard")
    else:
        return "❌ Invalid Credentials"

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/admin-dashboard")
def admin_dashboard():
    if 'role' not in session or session['role'] != 'admin':
        return redirect("/")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.name, u.email, up.id, up.filename, up.description, up.is_encrypted, up.upload_date, up.file_size
        FROM uploads up
        JOIN users u ON up.user_id = u.id
        ORDER BY up.upload_date DESC
    ''')
    uploads = cursor.fetchall()
    conn.close()
    
    return render_template("admin_dashboard.html", uploads=uploads)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/upload", methods=["POST"])
def upload_file():
    try:
        if 'user_id' not in session:
            return jsonify({"error": "Not logged in"}), 401
        
        filename = request.form.get("filename", "").strip()
        description = request.form.get("description", "").strip()
        is_encrypted = request.form.get("is_encrypted", "0")
        file_size = request.form.get("file_size", "0")
        
        if not filename:
            return jsonify({"error": "Filename is required"}), 400
        
        # Convert to int with defaults
        try:
            is_encrypted = int(is_encrypted)
        except (ValueError, TypeError):
            is_encrypted = 0
        
        try:
            file_size = float(file_size)
        except (ValueError, TypeError):
            file_size = 0.0
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO uploads (user_id, filename, description, is_encrypted, file_size) VALUES (?, ?, ?, ?, ?)",
            (session['user_id'], filename, description, is_encrypted, file_size)
        )
        conn.commit()
        conn.close()
        
        return jsonify({"success": True, "message": "File uploaded successfully!"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/get-admin-stats")
def get_admin_stats():
    if 'role' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Total uploads
    cursor.execute("SELECT COUNT(*) as total FROM uploads")
    total_uploads = cursor.fetchone()['total']
    
    # Encrypted vs Unencrypted
    cursor.execute("SELECT COUNT(*) as encrypted FROM uploads WHERE is_encrypted = 1")
    encrypted = cursor.fetchone()['encrypted']
    unencrypted = total_uploads - encrypted
    
    # Total users
    cursor.execute("SELECT COUNT(*) as total FROM users WHERE role = 'user'")
    total_users = cursor.fetchone()['total']
    
    conn.close()
    
    return jsonify({
        "total_uploads": total_uploads,
        "encrypted": encrypted,
        "unencrypted": unencrypted,
        "total_users": total_users
    })


@app.route("/get-all-uploads")
def get_all_uploads():
    if 'role' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.name, u.email, up.id, up.filename, up.description, up.is_encrypted, up.upload_date, up.file_size
        FROM uploads up
        JOIN users u ON up.user_id = u.id
        ORDER BY up.upload_date DESC
    ''')
    uploads = cursor.fetchall()
    conn.close()
    
    # Convert to list of dicts
    uploads_list = []
    for upload in uploads:
        uploads_list.append({
            'name': upload['name'],
            'email': upload['email'],
            'id': upload['id'],
            'filename': upload['filename'],
            'description': upload['description'],
            'is_encrypted': upload['is_encrypted'],
            'upload_date': upload['upload_date'],
            'file_size': upload['file_size']
        })
    
    return jsonify({"uploads": uploads_list})


@app.route("/get-all-users")
def get_all_users():
    if 'role' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, email, role FROM users ORDER BY id DESC')
    users = cursor.fetchall()
    conn.close()
    
    # Convert to list of dicts
    users_list = []
    for user in users:
        users_list.append({
            'id': user['id'],
            'name': user['name'],
            'email': user['email'],
            'role': user['role']
        })
    
    return jsonify({"users": users_list})


@app.route("/search", methods=["POST"])
def search():
    data = request.json
    query = data["query"]

    # NLP Spell Correction
    blob = TextBlob(query)
    corrected_word = str(blob.correct())

    return jsonify({
        "original": query,
        "corrected": corrected_word
    })



if __name__ == "__main__":
    app.run(debug=True)