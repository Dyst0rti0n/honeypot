import sqlite3

def init_db():
    conn = sqlite3.connect('honeypot.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (timestamp TEXT, protocol TEXT, address TEXT, port INTEGER, details TEXT)''')
    conn.commit()
    conn.close()

def log_to_db(timestamp, protocol, address, port, details):
    conn = sqlite3.connect('honeypot.db')
    c = conn.cursor()
    c.execute("INSERT INTO logs (timestamp, protocol, address, port, details) VALUES (?, ?, ?, ?, ?)",
              (timestamp, protocol, address, port, details))
    conn.commit()
    conn.close()

# Initialize the database
init_db()
