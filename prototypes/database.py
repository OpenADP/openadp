import sqlite3

class Database:

    def __init__(self, dbName):
        self.con = sqlite3.connect(dbName)
        cur = self.con.cursor()
        res = cur.execute("SELECT name FROM sqlite_master WHERE name='shares'").fetchone()
        if res == None:
            print("Creating shares table")
            cur.execute("""CREATE TABLE shares(
                UID TEXT NOT NULL,
                DID TEXT NOT NULL,
                BID TEXT NOT NULL,
                x BLOB NOT NULL,
                y BLOB NOT NULL,
                bad_guesses INTEGER NOT NULL,
                max_guesses INTEGER NOT NULL,
                expiration IINTEGER NOT NULL,
                PRIMARY KEY(UID, DID, BID))""")
        else:
            print("Found shares table")

    def __del__(self):
        self.con.close()

    def insert(self, UID, DID, BID, x, y, max_guesses, expiration):
        sql = """REPLACE INTO shares(UID, DID, BID, x, y, bad_guesses, max_guesses, expiration)
                 VALUES(?,?,?,?,?,?,?,?)"""
        cur = self.con.cursor()
        cur.execute(sql, (UID, DID, BID, x, y, 0, max_guesses, expiration))
        self.con.commit()

    def listBackups(self, UID):
        sql = "SELECT DID, BID FROM shares WHERE UID = ?"
        cur = self.con.cursor()
        return cur.execute(sql, [UID]).fetchall()

    def lookup(self, UID, DID, BID):
        sql = """SELECT x, y, bad_guesses, max_guesses, expiration FROM shares
                 WHERE UID = ? AND DID = ? AND BID = ?"""
        cur = self.con.cursor()
        return cur.execute(sql, [UID, DID, BID]).fetchall()
        

if __name__ == '__main__':
    db = Database("openadp_test.db")
    expiration = 1906979047  # Some time in 2030.  This is seconds since 1970.
    UID = "waywardgeek@gmail.com"
    DID = "Ubuntu beast Alienware laptop"
    db.insert(UID, DID, "file://archive.tgz", 1, 234, 10, 1906979047)
    db.insert(UID, DID, "firefox_passwords://passwords.json", 1, 234, 10, 1906979047)
    print(db.listBackups(UID))
    print(db.lookup(UID, DID, "file://archive.tgz"))
