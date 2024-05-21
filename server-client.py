from secp256k1 import curve,scalar_mult
from bip import generate_keys_from_mnemonic, Bip39MnemonicGenerator, mnemonic_to_xpub, Bip44Changes, Bip44Coins, get_public_key_from_xpub
import random

print("Basepoint:\t", curve.g)

# Create mnemonic
mnemonic_generator = Bip39MnemonicGenerator()
mnemonic = mnemonic_generator.FromWordsNumber(12)
print("Mnemonic:", mnemonic)

# Get keys
fixed_path_s = "m/44'/0'/1'/0/1"
fixed_path = [Bip44Coins.BITCOIN, 1, Bip44Changes.CHAIN_EXT, 1]
server_priv_key, server_public_key = generate_keys_from_mnemonic(mnemonic, account=1)
client_priv_key, client_public_key = generate_keys_from_mnemonic(mnemonic, account=2)

# Get root xpub
master_path_s = "m/44'/0'/0'/0/0"
root_xpub = mnemonic_to_xpub(mnemonic, master_path_s)

# Get public_keys of server and client from xpub
get_public_key_from_xpub(root_xpub, derivation_path=fixed_path_s)

# Get session randoms
server_random  = random.randrange(1, curve.n)
server_random_message = scalar_mult(server_random, curve.g)

client_random  = random.randrange(1, curve.n)
client_random_message = scalar_mult(client_random, curve.g)

# Sign session random messages at server and client


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