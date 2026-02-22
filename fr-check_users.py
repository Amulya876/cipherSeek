import sqlite3

conn = sqlite3.connect('privseek.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()
cursor.execute('SELECT id, name, email, role FROM users')
users = cursor.fetchall()
print(f'Total users: {len(users)}')
for user in users:
    print(f'ID: {user["id"]}, Name: {user["name"]}, Email: {user["email"]}, Role: {user["role"]}')
conn.close()
