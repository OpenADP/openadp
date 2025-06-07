# Copyright 2025 OpenADP Authors.  This work is licensed under the Apache 2.0 license.
#
# This is a prototype of the server for OpenADP.  Currently (June 1, 2025), the
# design is only lightly documented in the root level README.md.  This
# prototype is meant to clarify that design and should work with both prototype
# and real clients.

import crypto
import database
import secrets
import sharing
import time

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Return a 16-bit length prefixed (little-endian) string.
def prefixed(a):
    l = len(a)
    if len(a) >= 1 << 16:
        raise Exception("Input string too long")
    prefix = int.to_bytes(l, 2, "little")
    return prefix + a

# Hash function mapping input parameters (with length prefixes) to a point.
def H(UID, DID, BID, pin):
    s = crypto.sha256(prefixed(UID) + prefixed(DID) + prefixed(BID) + pin)
    yBase = int.from_bytes(s, "little")
    sign = yBase >> 255
    yBase &= ((1 << 255) - 1)
    counter = 0
    while True:
        y = yBase ^ counter
        x = crypto.recover_x(y, sign)
        if x != None:
            # Force the point to be in a group of order crypto.q
            P = crypto.expand((x, y))
            P = crypto.point_mul8(P)
            if crypto.point_valid(P):
                return P
        counter += 1

# P a point in expanded format.
def deriveEncKey(P):
    p = crypto.point_compress(P)
    hkdf = HKDF(hashes.SHA256(), 32, b"", b"OpenADP enc_key derivation");
    return hkdf.derive(p)

def checkRegisterInputs(UID, DID, BID, x, y, max_guesses, expiration):
    MAX_LEN = 512
    if len(UID) > MAX_LEN:
        return Exception("UID too long")
    if len(DID) > MAX_LEN:
        return Exception("DID too long")
    if len(BID) > MAX_LEN:
        return Exception("BID too long")
    if x > 1000:
        return Exception("Too many shares")
    if len(y) > 32:
        return Exception("Y share too large")
    if max_guesses > 1000:
        return Exception("Max guesses too high")
    seconds_since_epoch = int(time.time())
    # I guess we'll let 0 represent no expiration.
    if expiration < seconds_since_epoch and expiration != 0:
        return Exception("Expiration is in the past")
    return True

def registerSecret(db, UID, DID, BID, version, x, y, max_guesses, expiration):
    res = checkRegisterInputs(UID, DID, BID, x, y, max_guesses, expiration)
    if res != True:
        return res
    db.insert(UID, DID, BID, version, x, y, 0, max_guesses, expiration)
    return True

def checkRecoverInputs(UID, DID, BID, B):
    MAX_LEN = 512
    if len(UID) > MAX_LEN:
        return Exception("UID too long")
    if len(DID) > MAX_LEN:
        return Exception("DID too long")
    if len(BID) > MAX_LEN:
        return Exception("BID too long")
    if not crypto.point_valid(B):
        return Exception("Invalid point")
    return True

# The guess_num parameter prevents accidental replay causing counters to
# increment more than once.  This makes the recoverSecret RPC idempotent.
def recoverSecret(dbN, UID, DID, BID, B, guess_num):
    res = checkRecoverInputs(UID, DID, BID, B)
    if res != True:
        return res
    res = db.lookup(UID, DID, BID)
    if res == None:
        return Exception("Not found")
    (version, x, y, num_guesses, max_guesses, expiration) = res
    if guess_num != num_guesses:
        return Exception("Expecting guess_num = %d" % num_guesses)
    if num_guesses >= max_guesses:
        return Exception("Too many guesses")
    num_guesses += 1
    db.insert(UID, DID, BID, version, x, y, num_guesses, max_guesses, expiration)
    y = int.from_bytes(y, "little")
    siB = crypto.unexpand(crypto.point_mul(y, B))
    return (version, x, siB, num_guesses, max_guesses, expiration)

def listBackups(db, UID):
    return database.listBackups(UID)
    
if __name__ == '__main__':
    def findGuessNum(db, UID, DID, BID):
        backup = db.lookup(UID, DID, BID)
        if backup == None:
            return None
        return backup[3]
        
    UID = b"waywardgeek@gmail.com"
    DID = b"Ubuntu beast Alienware laptop"
    BID = b"file://archive.tgz"
    pinVal = secrets.randbelow(10000)
    print("pin =", pinVal)
    pin = int.to_bytes(pinVal, 2, "little")
    U = H(UID, DID, BID, pin)
    print("U =", crypto.unexpand(U))
    p = crypto.q
    r = secrets.randbelow(p - 1) + 1
    r_inv = pow(r, -1, p)
    B = crypto.point_mul(r, U)
    s = secrets.randbelow(p)
    S = crypto.point_mul(s, U)
    print("S =", crypto.unexpand(S))
    enc_key = deriveEncKey(S)
    print("enc_key =", enc_key)
    T = 2
    N = 3
    shares = sharing.makeRandomShares(s, T, N)
    print("s =", s)
    print("shares =", shares)
    for (x, y) in shares:
        yEnc = int.to_bytes(y, 32, "little")
        dbName = "openadp_test%d.db" % x
        db = database.Database(dbName)
        registerSecret(db, UID, DID, BID, 1, x, yEnc, 10, 10000000000)
        for guess_num in range(secrets.randbelow(10)):
            res = recoverSecret(db, UID, DID, BID, B, guess_num)
    assert crypto.point_equal(U, crypto.point_mul(r_inv, B))
    print("B =", crypto.unexpand(B))
    recShares = []
    for x, _ in shares:
        dbName = "openadp_test%d.db" % x
        db = database.Database(dbName)
        guess_num = findGuessNum(db, UID, DID, BID)
        res = recoverSecret(db, UID, DID, BID, B, guess_num)
        assert not isinstance(res, BaseException)
        (version, x, siB, num_guesses, max_guesses, expiration) = res
        print("siB =", siB)
        recShares.append((x, siB))
    print("recShares =", recShares)
    recSB = sharing.recoverSB([recShares[0], recShares[2]])
    recS = crypto.point_mul(r_inv, crypto.expand(recSB))
    print("recS =", crypto.unexpand(recS))
    assert crypto.point_equal(recS, S)
    rec_enc_key = deriveEncKey(recS)
    assert enc_key == rec_enc_key
