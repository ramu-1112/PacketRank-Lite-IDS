import sqlite3

conn = sqlite3.connect('packets.db')
cs = conn.cursor()

query = """
CREATE TABLE IF NOT EXISTS packets(
    id INTEGER PRIMARY KEY,
    time TEXT,
    src TEXT,
    dst TEXT,
    protocol TEXT,
    len INTEGER,
    info TEXT,
    raw TEXT
)
"""
query1 = """INSERT INTO packets(src,dst) 
            VALUES(?,?)"""
cs.execute(query)
cs.execute(query1,("1.1.1","222"))
conn.commit()