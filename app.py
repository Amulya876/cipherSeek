from flask import Flask, request, jsonify, render_template
import sqlite3
import hashlib
import uuid
import boto3
import os
import json
from io import BytesIO
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PyPDF2 import PdfReader
import re


def validate_credentials(user_id, password):
    # Username: 4–30 chars, letters + numbers only
    if not user_id or not re.fullmatch(r"[A-Za-z0-9]{4,30}", user_id):
        return "Username must be 4-30 characters (letters and numbers only)"

    # Password: 8–64 chars
    if not password or len(password) < 8 or len(password) > 64:
        return "Password must be 8-64 characters"

    return None


app = Flask(__name__)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user_id = request.form.get("user_id")
        password = request.form.get("password")

        # Simple login check (you can improve later)
        if user_id and password:
            return render_template("dashboard.html")
        else:
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


# ==============================
# AWS CONFIG (SET ENV VARIABLES)
# ==============================

S3_BUCKET = "cipherseek-storage-2026"
S3_REGION = "ap-south-1"

s3 = boto3.client(
    "s3",
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name=S3_REGION
)


# ==============================
# DATABASE
# ==============================

DATABASE = "database.db"


def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            document_id TEXT PRIMARY KEY,
            owner_user_id TEXT,
            original_filename TEXT,
            aws_s3_key TEXT,
            file_size INTEGER
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS keyword_index (
            document_id TEXT,
            keyword_hash TEXT
        )
    """)

    conn.commit()
    conn.close()


init_db()


# ==============================
# KEY GENERATION
# ==============================

def generate_key(password, user_id):
    sha = hashlib.sha256((password + user_id).encode()).digest()
    return sha[:16]


# ==============================
# AES ENCRYPT / DECRYPT
# ==============================

def encrypt_file(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ciphertext


def decrypt_file(data, key):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


# ==============================
# TEXT EXTRACTION
# ==============================

def extract_text_from_pdf(file_content):
    try:
        pdf_file = BytesIO(file_content)
        reader = PdfReader(pdf_file)
        text = ""

        for page in reader.pages:
            text += page.extract_text() or ""

        return text
    except:
        return ""


def extract_text_from_file(file_content, filename):
    if filename.endswith(".pdf"):
        return extract_text_from_pdf(file_content)
    elif filename.endswith(".txt"):
        return file_content.decode("utf-8", errors="ignore")
    else:
        return file_content.decode("utf-8", errors="ignore")


# ==============================
# KEYWORD EXTRACTION
# ==============================

def extract_keywords(text):
    stopwords = {
        "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
        "is", "was", "are", "be", "been", "being", "have", "has", "had",
        "do", "does", "did", "will", "would", "could", "should",
        "this", "that", "these", "those", "of", "from", "by", "with"
    }

    words = text.lower().split()
    keywords = []

    for word in words:
        clean = "".join(c for c in word if c.isalnum())
        if clean and len(clean) > 3 and clean not in stopwords:
            keywords.append(clean)

    return list(set(keywords))[:100]


# ==============================
# HASH KEYWORD (USER ISOLATED)
# ==============================

def hash_keyword(keyword, user_id, password):
    return hashlib.sha256(
        (keyword + user_id + password).encode()
    ).hexdigest()


# ==============================
# HOME
# ==============================


@app.route("/")
def home():
    return render_template("login.html")


# ==============================
# UPLOAD
# ==============================

@app.route("/upload", methods=["POST"])
def upload():
    try:
        user_id = request.form.get("user_id")
        password = request.form.get("password")

        error = validate_credentials(user_id, password)
        if error:
            return jsonify({"error": error}), 400

        file = request.files.get("file")

        if not user_id or not password or not file:
            return jsonify({"error": "Missing fields"}), 400

        document_id = str(uuid.uuid4())
        file_content = file.read()

        # Generate AES key
        key = generate_key(password, user_id)

        # Extract text + keywords
        text = extract_text_from_file(file_content, file.filename)
        keywords = extract_keywords(text)

        print("\n====== EXTRACTED KEYWORDS ======")
        print(keywords)
        print("================================\n")

        # Encrypt file
        encrypted_file = encrypt_file(file_content, key)
        s3_key = f"{document_id}.bin"

        # Upload encrypted file to S3
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=encrypted_file
        )

        # Store metadata + keyword hashes
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()

        c.execute("""
            INSERT INTO documents VALUES (?, ?, ?, ?, ?)
        """, (
            document_id,
            user_id,
            secure_filename(file.filename),
            s3_key,
            len(file_content)
        ))

        for kw in keywords:
            kw_hash = hash_keyword(kw, user_id, password)
            c.execute("""
                INSERT INTO keyword_index VALUES (?, ?)
            """, (document_id, kw_hash))

        conn.commit()
        conn.close()

        return jsonify({
            "message": "Document uploaded securely",
            "document_id": document_id,
            "keywords_extracted": len(keywords)
        }), 201

    except Exception as e:
        print("UPLOAD ERROR:", e)
        return jsonify({"error": str(e)}), 500


# ==============================
# SEARCH
# ==============================

@app.route("/search", methods=["POST"])
def search():
    try:
        data = request.get_json()

        user_id = data.get("user_id")
        password = data.get("password")
        keyword = data.get("keyword")

        error = validate_credentials(user_id, password)
        if error:
            return jsonify({"documents": [], "error": error}), 400

        if not user_id or not password or not keyword:
            return jsonify({"documents": []})

        search_hash = hash_keyword(keyword.lower(), user_id, password)

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()

        c.execute("""
            SELECT documents.document_id
            FROM documents
            JOIN keyword_index
            ON documents.document_id = keyword_index.document_id
            WHERE documents.owner_user_id = ?
            AND keyword_index.keyword_hash = ?
        """, (user_id, search_hash))

        rows = c.fetchall()
        conn.close()

        documents = [{"document_id": row[0]} for row in rows]

        return jsonify({"documents": documents})

    except Exception as e:
        print("SEARCH ERROR:", e)
        return jsonify({"error": str(e)}), 500


# ==============================
# DOWNLOAD
# ==============================

@app.route("/download/<document_id>", methods=["POST"])
def download(document_id):
    try:
        data = request.get_json()

        user_id = data.get("user_id")
        password = data.get("password")

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()

        c.execute("""
            SELECT aws_s3_key
            FROM documents
            WHERE document_id = ?
            AND owner_user_id = ?
        """, (document_id, user_id))

        result = c.fetchone()
        conn.close()

        if not result:
            return jsonify({"error": "Document not found"}), 404

        s3_key = result[0]

        obj = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
        encrypted_data = obj["Body"].read()

        key = generate_key(password, user_id)
        decrypted_data = decrypt_file(encrypted_data, key)

        return decrypted_data, 200, {
            "Content-Type": "application/octet-stream",
            "Content-Disposition": f"attachment; filename={document_id}"
        }

    except Exception as e:
        print("DOWNLOAD ERROR:", e)
        return jsonify({"error": str(e)}), 500


# ==============================
# RUN
# ==============================

if __name__ == "__main__":
    app.run(debug=True)