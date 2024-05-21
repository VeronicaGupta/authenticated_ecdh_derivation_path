import os
import hashlib
import hmac
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes, Secp256k1Point

def generate_keys_from_mnemonic(mnemonic, path):
    # Get path
    coin_type, account, change, address_index = path

    # Generate the seed from the mnemonic
    seed = Bip39SeedGenerator(mnemonic).Generate()
    
    # Create a BIP44 object from the seed
    bip44_ctx = Bip44.FromSeed(seed, coin_type)
    
    # Derive keys according to the derivation path
    derived_key = bip44_ctx.Purpose().Coin().Account(account).Change(change).AddressIndex(address_index)

    # Get the public_key points
    pub_key_bytes = derived_key.PublicKey().RawUncompressed()
    try:
        pub_key_point = Secp256k1Point.FromBytes(pub_key_bytes[1:])
        public_key_tuple = (pub_key_point.X(), pub_key_point.Y())
    except ValueError as e:
        print("Failed to convert public key bytes to point:", str(e))
        public_key_tuple = None

    # Return the private key and public key
    return derived_key.PrivateKey().Raw().ToInt(), public_key_tuple


# Example usage
# Initialize the generator (if needed based on your library version)
# mnemonic_generator = Bip39MnemonicGenerator()

# # Generate a mnemonic with 12 words
# mnemonic = mnemonic_generator.FromWordsNumber(12)
# print("Mnemonic:", mnemonic)
# private_key, public_key = generate_keys_from_mnemonic(mnemonic)
# print("Private Key:", private_key)
# print("Public Key:", public_key)


from bip32 import BIP32

def mnemonic_to_xpub(mnemonic, derivation_path):
    seed = Bip39SeedGenerator(mnemonic).Generate()
    bip32 = BIP32.from_seed(seed)

    # xpriv = bip32.get_xpriv_from_path("m/84'/0'/0'/0/1")
    root_xpub = bip32.get_xpub_from_path(derivation_path)

    return root_xpub

from bip32 import BIP32
from binascii import unhexlify

def get_public_key_from_xpub(xpub, derivation_path):
    # Initialize the BIP32 object with the xpub
    bip32 = BIP32.from_xpub(xpub)
    
    # Derive the public key from the xpub at the specified derivation path
    public_key = bip32.get_pubkey_from_path(derivation_path)
    
    # Convert the public key to hex format for display or use
    public_key_hex = public_key.hex()
    
    return public_key_hex

# # Example usage
# xpub = "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKbD2Tu1L4iVVKxydvrEJq516BMQRH9wSbLCG6Q8w4tEpD5R8JPi8tB9whfEKeqzAABHVZFeY6ZmUQ"
# derivation_path = "m/0/0"

# derived_public_key = derive_public_key(xpub, derivation_path)
# print("Derived Public Key:", derived_public_key)
