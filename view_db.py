import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

print("\n--- DOCUMENTS TABLE ---")
for row in cursor.execute("SELECT * FROM documents"):
    print(row)

print("\n--- KEYWORD INDEX TABLE ---")
for row in cursor.execute("SELECT * FROM keyword_index"):
    print(row)

conn.close()