from secp256k1 import curve,scalar_mult, point_add
from bip import generate_keys_from_mnemonic, Bip39MnemonicGenerator, mnemonic_to_xpub, Bip44Changes, Bip44Coins, get_public_key_from_xpub, ecdsa_sign, ecdsa_verify
import random
from hashlib import sha256
from aes import encrypt_aes, decrypt_aes

print("Basepoint:\t", curve.g)

# Master device-> Create mnemonic
mnemonic_generator = Bip39MnemonicGenerator() # mnemonic of the master device
mnemonic = "uphold album symbol kiss gift sadness shock ginger dignity pumpkin skin junk" #mnemonic_generator.FromWordsNumber(12)
print("Mnemonic:", mnemonic)




# Server-> Get keys
s = 10
server_path = f"m/{s}/{s}/{s}/{s}/{s}/{s}"
server_priv_key = generate_keys_from_mnemonic(mnemonic, server_path)
server_pub_key = scalar_mult(server_priv_key, curve.g)


# Client-> Get keys
s = 20
client_path = f"m/{s}/{s}/{s}/{s}/{s}/{s}"
client_priv_key = generate_keys_from_mnemonic(mnemonic, client_path)
client_pub_key = scalar_mult(client_priv_key, curve.g)





# Server & Client-> Get XPUB
root_xpub = mnemonic_to_xpub(mnemonic, "m") # Step not required if client already has the root_xpub




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



# Client-> Verify Server Session Randoms 
derived_server_public_key = get_public_key_from_xpub(root_xpub, server_path)
is_server_to_client_data_valid = ecdsa_verify(derived_server_public_key, server_random_pubkey_message, server_signature)
print("Sesssion key sent from server to client is", is_server_to_client_data_valid)

derived_server_random_pubkey = int(server_random_pubkey_message[:64], 16), int(server_random_pubkey_message[64:], 16)
x, y = scalar_mult(client_random, derived_server_random_pubkey) # r2*r1.G
client_session_aes_key = int(x).to_bytes(32, "big")
x, y = point_add(client_random_pub_key, derived_server_random_pubkey) # r2.G + r1.G

client_session_id = int(sha256(f"{x}{y}".encode()).hexdigest(), 16).to_bytes(32, "big")[:16] # same would be derived at the server side
print("Client key =======", client_session_aes_key.hex())
print("Client iv ========", client_session_id.hex())


# Server-> Verify Client Session Randoms
derived_client_public_key = get_public_key_from_xpub(root_xpub, client_path)
is_client_to_server_data_valid = ecdsa_verify(derived_client_public_key, client_random_pubkey_message, client_signature)
print("Sesssion key sent from client to server is", is_client_to_server_data_valid)

derived_client_random_pubkey = int(client_random_pubkey_message[:64], 16), int(client_random_pubkey_message[64:], 16)
x, y = scalar_mult(server_random, derived_client_random_pubkey) # r1*r2.G
server_session_aes_key = int(x).to_bytes(32, "big")
x, y = point_add(server_random_pub_key, derived_client_random_pubkey) # r1.G + r2.G

server_session_id = int(sha256(f"{x}{y}".encode()).hexdigest(), 16).to_bytes(32, "big")[:16] # same would be derived at the client side
print("Server key =======", server_session_aes_key.hex())
print("Srever iv ========", server_session_id.hex())





# Client-> Send Encrypted message 
message_sent_to_server = encrypt_aes(b"secret_message", client_session_aes_key, client_session_id)

# Server-> Decrypt Message
message = decrypt_aes(message_sent_to_server, server_session_aes_key, server_session_id)
print("Server Decrypted", message)