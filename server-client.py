from secp256k1 import curve,scalar_mult, point_add
from bip import generate_keys_from_mnemonic, Bip39MnemonicGenerator, mnemonic_to_xpub, Bip44Changes, Bip44Coins, get_public_key_from_xpub, ecdsa_sign, ecdsa_verify, get_public_key
import random
from hashlib import sha256
from aes import encrypt_aes, decrypt_aes

# print("Basepoint:\t", curve.g)

# Master device-> Create mnemonic
mnemonic_generator = Bip39MnemonicGenerator() # mnemonic of the master device
mnemonic = "uphold album symbol kiss gift sadness shock ginger dignity pumpkin skin junk" #mnemonic_generator.FromWordsNumber(12)
# print("Mnemonic:", mnemonic)




# Server-> Get keys
xpub_path_at_client = "m/1000'/0'/2'/0"
server_path = f"{xpub_path_at_client}/66/77"
server_priv_key = generate_keys_from_mnemonic(mnemonic, server_path)
server_pub_key = scalar_mult(server_priv_key, curve.g)



# Client-> Get keys
pubkey_path_at_server =  "m/1000'/1'/2'/0"
client_path = f"{pubkey_path_at_server}/88/99"
client_priv_key = generate_keys_from_mnemonic(mnemonic, client_path)
client_pub_key = scalar_mult(client_priv_key, curve.g)

print("derivation_path of public_key of device saved at server :", pubkey_path_at_server)
print("derivation_path of xpub  of saved at client :", xpub_path_at_client)

print("server_path :", server_path)
print("client_path :", client_path)


# Server-> Contains DB mapping device_id -> public key

# Client-> Get XPUB
root_xpub = mnemonic_to_xpub(mnemonic, xpub_path_at_client) # Step not required if client already has the root_xpub



# Server-> Sign Session Randoms
server_random  = random.randrange(1, curve.n)
server_random_pub_key = (server_pub_x, server_pub_y) = scalar_mult(server_random, curve.g)
server_pub_x_hex, server_pub_y_hex = format(server_pub_x, '064x'), format(server_pub_y, '064x')
server_random_pubkey_message = f"{server_pub_x_hex}{server_pub_y_hex}"
server_signature = ecdsa_sign(server_priv_key, server_random_pubkey_message)

# Client-> Sign Session Randoms
client_random  = random.randrange(1, curve.n)
client_random_pub_key = (client_pub_x, client_pub_y) = scalar_mult(client_random, curve.g)
client_pub_x_hex, client_pub_y_hex = format(client_pub_x, '064x'), format(client_pub_y, '064x')
client_random_pubkey_message = f"{client_pub_x_hex}{client_pub_y_hex}"
client_signature = ecdsa_sign(client_priv_key, client_random_pubkey_message)


message = b"secret_message"
print("\nOriginal Message ====", message)

# Client-> Verify Server Session Randoms 
print("\nCLIENT->")
derived_server_public_key = get_public_key_from_xpub(root_xpub, "m/66/77")
is_server_to_client_data_valid = ecdsa_verify(derived_server_public_key, server_random_pubkey_message, server_signature)
print("Server_Random_Public_Key valid :", is_server_to_client_data_valid)

derived_server_random_pubkey = int(server_random_pubkey_message[:64], 16), int(server_random_pubkey_message[64:], 16)
x, y = scalar_mult(client_random, derived_server_random_pubkey) # r2*r1.G
client_session_aes_key = int(x).to_bytes(32, "big")
x, y = point_add(client_random_pub_key, derived_server_random_pubkey) # r2.G + r1.G

client_session_id = int(sha256(f"{x}{y}".encode()).hexdigest(), 16).to_bytes(32, "big")[:16] # same would be derived at the server side
print("Session_key  :", client_session_aes_key.hex())
print("Sesssion_id  :", client_session_id.hex())

message_sent_to_server = encrypt_aes(message, client_session_aes_key, client_session_id)
print("\nClient Encrypted Message ===", message_sent_to_server)

# Server-> Verify Client Session Randoms
print("\nSERVER->")
saved_client_public_key = get_public_key(mnemonic, client_path) # public key saved at server
is_client_to_server_data_valid = ecdsa_verify(saved_client_public_key, client_random_pubkey_message, client_signature)
print("Client_Random_Public_Key valid :", is_client_to_server_data_valid)

derived_client_random_pubkey = int(client_random_pubkey_message[:64], 16), int(client_random_pubkey_message[64:], 16)
x, y = scalar_mult(server_random, derived_client_random_pubkey) # r1*r2.G
server_session_aes_key = int(x).to_bytes(32, "big")
x, y = point_add(server_random_pub_key, derived_client_random_pubkey) # r1.G + r2.G

server_session_id = int(sha256(f"{x}{y}".encode()).hexdigest(), 16).to_bytes(32, "big")[:16] # same would be derived at the client side
print("Session_key :", server_session_aes_key.hex())
print("Srever iv  :", server_session_id.hex())

message = decrypt_aes(message_sent_to_server, server_session_aes_key, server_session_id)
print("\nServer Decrypted Message =", message)
