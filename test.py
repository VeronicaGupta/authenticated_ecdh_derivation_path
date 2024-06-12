import random
from secp256k1 import curve,scalar_mult, generate_public_key

x = random.randrange(1, curve.n)
xG = scalar_mult(x, curve.g)
    
print(x, format(x, '064x'))
print(xG, format(xG[0], '064x'), format(xG[1], '064x'))

print(generate_public_key(xG))