import secrets
from sympy.ntheory import sqrt_mod


class EllipticCurve:
    
    def __init__(self,a,b,p):
        self.a = a
        self.b = b
        self.p = p

    def IsValidPoint(self,x,y):
        return (y**2 - (x**3 + self.a + self.b)) % self.p == 0
    
    def PointAddition(self, P, Q):
        if P is None: return Q
        if Q is None: return P

        x1, y1 = P
        x2, y2 = Q

        if P == Q:
            lam = (3*x1**2 + self.a) * pow(2*y1, -1, self.p) % self.p
        else:
            lam = (y2 - y1) * pow(x2 - x1, -1, self.p) % self.p

        x3 = (lam**2 - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p

        return (x3, y3)

    def scalar_multiplication(self, k, P):
        R = None  # result
        Q = P

        while k:
            if k & 1:
                R = self.PointAddition(R, Q)
            Q = self.PointAddition(Q, Q)
            k >>= 1
        
        return R

p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = -3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162CB8B8E2F14E79A8943C3FE0B5C60180)

curve = EllipticCurve(a, b, p)

# Key generation
private_key = secrets.randbelow(p)
public_key = curve.scalar_multiplication(private_key, G)

print("private key:", private_key)
print("public key:", public_key)

# Computing y from x
def compute_y(curve, x):
    y_squared = (x**3 + curve.a * x + curve.b) % curve.p
    y = sqrt_mod(y_squared, curve.p, all_roots=True)

    if y is None:
        raise ValueError("No valid y found for x")
    y = y[0]

    return y

def encrypt_key(curve, G, public_key, aes_key, k=None):
    aes_key = int(aes_key, 16)  # Convert the hex AES key to an integer
    k = k or secrets.randbelow(curve.p)
    i = k - 1
    while i > 0:
        x = (aes_key * k + i) % curve.p
        try:
            y = compute_y(curve, x)
            Pm = (x, y)  # Key encoded as (x, y)
            break
        except:
            i -= 1
            if i <= 0:
                raise RuntimeError("Unable to find valid (x, y) pair.")
    # Compute ciphertext
    print("Pm:", Pm)
    Ciphertext1 = curve.scalar_multiplication(k, G)
    Ciphertext2 = curve.PointAddition(Pm, curve.scalar_multiplication(k, public_key))  # Pm + k* public key
    
    return Ciphertext1, Ciphertext2, k, i

# Decryption
def decryption_key(curve, private_key, CiText1, CiText2, k, i):
    shared_secret = curve.scalar_multiplication(private_key, CiText1)

    neg_shared_secret = (shared_secret[0], (-shared_secret[1]) % curve.p)
    Pm = curve.PointAddition(CiText2, neg_shared_secret)

    aes_key = ((Pm[0] - i) * pow(k, -1, curve.p)) % curve.p

    return aes_key

# Example usage
aes_key = input('Enter AES key (hexadecimal):')  # Example AES key (as hex string)

# Encrypt the AES key
Cm1, Cm2, k, i = encrypt_key(curve, G, public_key, aes_key)
print("Encrypted AES Key:", Cm1)
print(Cm2)

# Decrypt the AES key
decrypted_key = decryption_key(curve, private_key, Cm1, Cm2, k, i)
print("Decrypted AES Key:", hex(decrypted_key)[2:])

# Verify correctness
assert aes_key == hex(decrypted_key)[2:], "Decryption failed!"
print("Encryption and decryption successful!")
