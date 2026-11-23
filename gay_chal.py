import math
import secrets
from sympy import nextprime

BITS = 224
UNKNOWN_BITS = 40
FLAG = b"REDACTED"


def random_prime(bits):
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        prime = int(nextprime(candidate))
        if prime.bit_length() == bits:
            return prime


def ou_decrypt(ciphertext, prime, generator):
    modulus = prime * prime
    a = pow(ciphertext, prime - 1, modulus)
    b = pow(generator, prime - 1, modulus)
    assert (a - 1) % prime == 0
    assert (b - 1) % prime == 0
    return ((a - 1) // prime) * pow((b - 1) // prime, -1, prime) % prime


p = random_prime(BITS)
q = random_prime(BITS)
while p == q:
    q = random_prime(BITS)
n = p * p * q
while True:
    g = secrets.randbelow(n - 3) + 2
    if math.gcd(g, n) == 1 and pow(g, p - 1, p*p) != 1:
        break
h = pow(g, n, n)
m = int.from_bytes(FLAG, 'big')

if not m < p:
    raise ValueError('FLAG exceeds plaintext space Z_p')
r = secrets.randbelow(n - 1) + 1
c = pow(g, m, n) * pow(h, r, n) % n
assert ou_decrypt(c, p, g) == m

print("n = ", n)
print("g = ", g)
print("c = ", c)
print("p_high = ", p >> UNKNOWN_BITS)


# n =  16656001461697083244088506751099457218307386673248128770422827105165484782412726724243602162392196801371977797257058804335055245964141822002417192793002696105046513657528481209964114475165968680052974951
# g =  5582151651616599507353000292570651496606773623124770209563728594588131547556207824408099856841651076611501593455020851065200442746332443388640639969810885404153135212165265544475636159169930763269101087
# c =  13323496195318260224772245745047290120015744110207321796218126904082415605119684263240595062128546234228569915309658423965782691385483685761147447685706319545820824126718710999960319879988954561321444065
# p_high =  24441472983365130028498215218566226383891559915282782099
