from secp256k1 import curve,scalar_mult
from bip import generate_keys_from_mnemonic, Bip39MnemonicGenerator, Bip44Coins, Bip44Changes
import random

fixed_path = [Bip44Coins.BITCOIN, 0, Bip44Changes.CHAIN_EXT, 0]
print("Basepoint:\t", curve.g)

mnemonic_generator = Bip39MnemonicGenerator()
mnemonic = mnemonic_generator.FromWordsNumber(12)
print("Mnemonic:", mnemonic)
a, a_pub = generate_keys_from_mnemonic(mnemonic, fixed_path)
b, b_pub = generate_keys_from_mnemonic(mnemonic, fixed_path)

# could be a random key-pair also
# a  = random.randrange(1, curve.n)
# a_pub = scalar_mult(a, curve.g)
# b = random.randrange(1, curve.n)
# b_pub = scalar_mult(b, curve.g)

x  = random.randrange(1, curve.n)
xG = scalar_mult(x, curve.g)
y  = random.randrange(1, curve.n)
yG = scalar_mult(y, curve.g)


Bob_send = scalar_mult(y, a_pub) # (y) aG
Bob_send = scalar_mult(b, Bob_send) # (yb) aG


Alice_send = scalar_mult(x, b_pub) # (x) bG
Alice_send = scalar_mult(a, Alice_send) # (xa) bG


k_a = scalar_mult(x, Bob_send) # x (yb) aG
k_b = scalar_mult(y, Alice_send) # y ( xa) bG

print("\nAlice\'s secret key (a):\t", a)
print("Alice\'s public key:\t", a_pub)
print("\nBob\'s secret key (b):\t", b)
print("Bob\'s public key:\t", b_pub)

print("==========================")

print("\nAlice\'s session secret key (a):\t", x)
print("Alice\'s  session public key:\t", Alice_send)
print("\nBob\'s  session secret key (b):\t", y)
print("Bob\'s  session public key:\t", Bob_send)

print("\n==========================")
print("Alice\'s shared key:\t", k_a)
print("Bob\'s shared key:\t", k_b)

print("\n==========================")
print("abxyG: \t", (k_a[0]))

res=(a*b*x*y) % curve.n

res=scalar_mult(res, curve.g)

print("(abxy)G \t", (res[0]))