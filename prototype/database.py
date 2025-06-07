# Copyright 2025 OpenADP Authors.  This work is licensed under the Apache 2.0 license.
import sqlite3

class Database:

    def __init__(self, dbName):
        self.con = sqlite3.connect(dbName)
        cur = self.con.cursor()
        res = cur.execute("SELECT name FROM sqlite_master WHERE name='shares'").fetchone()
        if res == None:
            print("Creating shares table ", dbName)
            cur.execute("""CREATE TABLE shares(
                UID TEXT NOT NULL,
                DID TEXT NOT NULL,
                BID TEXT NOT NULL,
                version INTEGER NOT NULL,
                x INTEGER NOT NULL,
                y BLOB NOT NULL,
                num_guesses INTEGER NOT NULL,
                max_guesses INTEGER NOT NULL,
                expiration IINTEGER NOT NULL,
                PRIMARY KEY(UID, DID, BID))""")

    def __del__(self):
        self.con.close()

    def insert(self, UID, DID, BID, version, x, y, num_guesses, max_guesses, expiration):
        sql = """REPLACE INTO shares(UID, DID, BID, version, x, y, num_guesses, max_guesses, expiration)
                 VALUES(?,?,?,?,?,?,?,?,?)"""
        cur = self.con.cursor()
        cur.execute(sql, (UID.decode('utf-8'), DID.decode('utf-8'), BID.decode('utf-8'), version, x, y,
                    num_guesses, max_guesses, expiration))
        self.con.commit()

    def listBackups(self, UID):
        sql = "SELECT DID, BID, version, num_guesses, max_guesses, expiration FROM shares WHERE UID = ?"
        cur = self.con.cursor()
        return cur.execute(sql, [UID]).fetchall()

    def lookup(self, UID, DID, BID):
        sql = """SELECT version, x, y, num_guesses, max_guesses, expiration FROM shares
                 WHERE UID = ? AND DID = ? AND BID = ?"""
        cur = self.con.cursor()
        res = cur.execute(sql, [UID.decode('utf-8'), DID.decode('utf-8'), BID.decode('utf-8')]).fetchall()
        if res == None:
            return None
        assert len(res) == 1
        return res[0]

    def findGuessNum(self, UID, DID, BID):
        backup = self.lookup(UID, DID, BID)
        if backup == None:
            return None
        return backup[3]
    
if __name__ == '__main__':

    db = Database("openadp_test.db")
    expiration = 1906979047  # Some time in 2030.  This is seconds since 1970.
    UID = b"waywardgeek@gmail.com"
    DID = b"Ubuntu beast Alienware laptop"
    version = 1
    x = 1
    y = 234
    db.insert(UID, DID, b"file://archive.tgz", version, x, y, 0, 10, 1906979047)
    db.insert(UID, DID, b"firefox_passwords://passwords.json", version, x, y, 0, 10, 1906979047)
    print(db.listBackups(UID))
    print(db.lookup(UID, DID, b"file://archive.tgz"))
