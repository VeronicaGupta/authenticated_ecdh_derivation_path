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

from bip32 import BIP32

def generate_keys_from_mnemonic(mnemonic, derivation_path):
    # Generate seed from the mnemonic
    seed = Bip39SeedGenerator(mnemonic).Generate()

    # Create a BIP32 object from the seed
    bip32_ctx = BIP32.from_seed(seed)
    
    # Derive the private and public keys using the parsed path
    private_key = bip32_ctx.get_privkey_from_path(derivation_path)

    # Convert the private key to an integer
    private_key_int = int.from_bytes(private_key, 'big')

    return private_key_int

# # Example usage
# mnemonic_generator = Bip39MnemonicGenerator()
# mnemonic = mnemonic_generator.FromWordsNumber(12)
# print("Mnemonic:", mnemonic)
# derivation_path = "m/44'/0'/1'/0/1"
# private_key_int, public_key_tuple = generate_keys_from_mnemonic(mnemonic, derivation_path)
# print("Private Key:", private_key_int)
# print("Public Key:", public_key_tuple)


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
 
    root_xpub = bip32.get_xpub_from_path(derivation_path)

    return root_xpub

def get_public_key(mnemonic, derivation_path):
    seed = Bip39SeedGenerator(mnemonic).Generate()
    bip32 = BIP32.from_seed(seed)
 
    public_key = bip32.get_pubkey_from_path(derivation_path)

    return public_key.hex()


from bip32 import BIP32

def get_public_key_from_xpub(xpub, derivation_path):
    # Initialize the BIP32 object with the xpub
    # bip32 = BIP32.from_xpriv(xpriv)
    bip32 = BIP32.from_xpub(xpub)
    
    # Derive the public key from the xpub at the specified derivation path
    public_key = bip32.get_pubkey_from_path(derivation_path)
    
    return public_key.hex()


# # Example usage
# xpub = "xpub6GoyY1DVjqFqVFncEnMDJEWtUHv2SNHePSUoghR9Wputo6GvWzv2wk39KM3ApNMFcK5e2BfEiDrZuh5ZqeDSQSa2koTdp8f7nxevLngnHBH"
# derivation_path = "m/84'/0'/0'/0/1"

# derived_public_key = get_public_key_from_xpub(xpub, derivation_path)
# print("Derived Public Key:", derived_public_key)

import ecdsa
from ecdsa.util import sigencode_der

def ecdsa_sign(private_key_int, message):
    # Convert the private key integer to a SigningKey object
    curve = ecdsa.SECP256k1
    private_key = ecdsa.SigningKey.from_secret_exponent(private_key_int, curve)

    # Sign the message
    signature = private_key.sign(message.encode(), sigencode=sigencode_der)

    # Return the signature in hexadecimal format
    return signature.hex()

# Example usage
# private_key_int = 1234567890123456789012345678901234567890  # Example private key as an integer
# message = "Hello, world!"
# signature_hex = ecdsa_sign(private_key_int, message)
# print("ECDSA Signature:", signature_hex)

from ecdsa import VerifyingKey, BadSignatureError
from ecdsa.util import sigdecode_der
def ecdsa_verify(public_key_hex, message, signature_hex):
    # Convert the public key from hex to a VerifyingKey object
    public_key_bytes = bytes.fromhex(public_key_hex)
    vk = VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1)

    # Convert the signature from hex to bytes
    signature_bytes = bytes.fromhex(signature_hex)

    # Try to verify the signature
    try:
        return vk.verify(signature_bytes, message.encode(), sigdecode=sigdecode_der)
    except BadSignatureError:
        return False


# Example usage
# public_key_ints = (55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424)  # Example public key coordinates
# message = "Hello, world!"
# signature_hex = "3045022100b2d86671546947c43446383887f1192d34430261ad15881852b387790fecec690220691df05d83fb7bc0c5b1803dbff6e97f5f27cb07b51959bead916e4976542f04"  # Assume this is your ECDSA signature in hex

# is_valid = ecdsa_verify(public_key_ints, message, signature_hex)
# print("Is the signature valid?", is_valid)

