# See https://datatracker.ietf.org/doc/html/rfc8032

import hashlib

# Convert (x, y) to the expanded form (x, y, 1, x*y)
def expand_point(point):
    (x, y) = point
    return (x, y, 1, x*y % p)

def unexpand_point(point):
    (X, Y, Z, T) = point
    z_inv = modp_inv(Z)
    return (X*z_inv % p, Y*z_inv % p)

def sha256(s):
    return hashlib.sha256(s).digest()

# Base field Z_p
p = 2**255 - 19

def modp_inv(x):
    return pow(x, p-2, p)

# Curve constant
d = -121665 * modp_inv(121666) % p

# Group order
q = 2**252 + 27742317777372353535851937790883648493

## Then follows functions to perform point operations.

# Points are represented as tuples (X, Y, Z, T) of extended
# coordinates, with x = X/Z, y = Y/Z, x*y = T/Z

def point_add(P, Q):
    A, B = (P[1]-P[0]) * (Q[1]-Q[0]) % p, (P[1]+P[0]) * (Q[1]+Q[0]) % p;
    C, D = 2 * P[3] * Q[3] * d % p, 2 * P[2] * Q[2] % p;
    E, F, G, H = B-A, D-C, D+C, B+A;
    return (E*F, G*H, F*G, E*H);

# Computes Q = s * Q
def point_mul(s, P):
    Q = (0, 1, 1, 0)  # Neutral element
    while s > 0:
        if s & 1:
            Q = point_add(Q, P)
        P = point_add(P, P)
        s >>= 1
    return Q

def point_equal(P, Q):
    # x1 / z1 == x2 / z2  <==>  x1 * z2 == x2 * z1
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % p != 0:
        return False
    return True

## Now follows functions for point compression.

# Square root of -1
modp_sqrt_m1 = pow(2, (p-1) // 4, p)

# Compute corresponding x-coordinate, with low bit corresponding to
# sign, or return None on failure
def recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y*y-1) * modp_inv(d*y*y+1)
    if x2 == 0:
        if sign:
            return None
        else:
            return 0

    # Compute square root of x2
    x = pow(x2, (p+3) // 8, p)
    if (x*x - x2) % p != 0:
        x = x * modp_sqrt_m1 % p
    if (x*x - x2) % p != 0:
        return None

    if (x & 1) != sign:
        x = p - x
    return x

# Base point
g_y = 4 * modp_inv(5) % p
g_x = recover_x(g_y, 0)
G = (g_x, g_y, 1, g_x * g_y % p)

def point_compress(P):
    zinv = modp_inv(P[2])
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")

def point_decompress(s):
    if len(s) != 32:
        raise Exception("Invalid input length for decompression")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1

    x = recover_x(y, sign)
    if x is None:
        return None
    else:
        return (x, y, 1, x*y % p)

## These are functions for manipulating the private key.

def secret_expand(secret):
    if len(secret) != 32:
        raise Exception("Bad size of private key")
    h = sha256(secret)
    a = int.from_bytes(h, "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return a

def secret_to_public(secret):
    a = secret_expand(secret)
    return point_compress(point_mul(a, G))

#Compute candidate square root of x modulo p, with p = 3 (mod 4).
def sqrt4k3(x,p): return pow(x,(p + 1)//4,p)

#Compute candidate square root of x modulo p, with p = 5 (mod 8).
def sqrt8k5(x,p):
    y = pow(x,(p+3)//8,p)
    #If the square root exists, it is either y or y*2^(p-1)/4.
    if (y * y) % p == x % p: return y
    else:
        z = pow(2,(p - 1)//4,p)
        return (y * z) % p

#Decode a hexadecimal string representation of the integer.
def hexi(s): return int.from_bytes(bytes.fromhex(s),byteorder="big")

#Rotate a word x by b places to the left.
def rol(x,b): return ((x << b) | (x >> (64 - b))) & (2**64-1)

#From little endian.
def from_le(s): return int.from_bytes(s, byteorder="little")
