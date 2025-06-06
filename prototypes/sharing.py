# Shamir secret sharing from https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing.

import crypto
import secrets

def evalAt(poly, x, prime):
    """Evaluates polynomial (coefficient tuple) at x, used to generate a
    shamir pool in make_random_shares below.
    """
    x_pow = 1
    result = 0
    for coeff in poly:
        result = (result + coeff*x_pow) % prime
        x_pow = x_pow * x % prime
    return result

def makeRandomShares(secret, minimum, shares, prime=crypto.q):
    """
    Generates a random shamir pool for a given secret, returns share points.
    """
    if minimum > shares:
        raise ValueError("Pool secret would be irrecoverable.")
    poly = [secret] + [secrets.randbelow(prime) for i in range(minimum - 1)]
    points = [(i, evalAt(poly, i, prime))
              for i in range(1, shares + 1)]
    return points

def recoverSB(shares, prime=crypto.q):
    """
    Recover s*B from T shares s[i]*B.
        w[i] = product(j != i, x[i]/(x[i] - x[j])).
        s*B = sum(w[i]s[i]*B)
    """
    # Compute w[i] weights.
    w = []
    #import pdb; pdb.set_trace()
    for xj, _ in shares:
        numerator = 1
        denominator = 1
        for (xm, _) in shares:
            if xj != xm:
                numerator = numerator * xm % prime
                denominator = denominator * (xm - xj) % prime
        wi = numerator * pow(denominator, -1, prime) % prime
        w.append(wi)
    # The mathematician Edwards believes angles should be measured clockwise
    # from the Y axis rather than counter-clockwise from the X axis, and so he
    # decided just for his Edwards curve to ignore thousands of years of
    # mathematical precedence.  This is why the point corresponding to 0 is at
    # (0, 1), rather than (1, 0).  Ugh...
    sB = crypto.expand((0, 1))
    for i in range(len(shares)):
        (xi, siB) = shares[i]
        sB = crypto.point_add(sB, crypto.point_mul(w[i], crypto.expand(siB)))
    return crypto.unexpand(sB)

if __name__ == '__main__':

    p = crypto.q
    secret = secrets.randbelow(p)
    T = 9
    N = 15
    shares = makeRandomShares(secret, T, N)
    print("secret =", secret)
    sB = crypto.unexpand(crypto.point_mul(secret, crypto.G))
    print("sB =", sB)
    # Convert the y coordinate of each share into y*G
    for i in range(len(shares)):
        x, y = shares[i]
        yG = crypto.unexpand(crypto.point_mul(y, crypto.G))
        shares[i] = (x, yG)
    recSB = recoverSB(shares[:T])
    recSB2 = recoverSB(shares[N - T:])
    print("recB =", recSB)
    print("recB2 =", recSB2)
    assert recSB == recSB2
    assert sB == recSB
