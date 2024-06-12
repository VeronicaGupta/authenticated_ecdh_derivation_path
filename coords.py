from ecdsa import SECP256k1, ellipticcurve
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def compress_coords(cp):
    x, y = cp.x(), cp.y()
    compressed = bytearray(33)
    compressed[0] = 0x03 if y % 2 else 0x02
    compressed[1:] = x.to_bytes(32, byteorder='big')
    return compressed

def uncompress_coords(curve, compressed):
    # Extract prefix and x coordinate
    prefix = compressed[0]
    x = int.from_bytes(compressed[1:], byteorder='big')

    # Calculate y^2 = x^3 + a*x + b
    y_square = (x**3 + curve.a() * x + curve.b()) % curve.p()

    # Calculate y by finding the modular square root of y^2
    y = pow(y_square, (curve.p() + 1) // 4, curve.p())

    # Adjust y based on the prefix
    if (y % 2) != (prefix == 0x03):
        y = curve.p() - y

    return ellipticcurve.Point(curve, x, y)


curve = SECP256k1.curve

# The given uint8_t private key array
get_ec_random = [
    0x0b, 0x78, 0x9a, 0x1e, 0xb8, 0x0b, 0x7a, 0xac, 0x97, 0xa1, 0x54, 0xd7,
    0x0c, 0x5a, 0x53, 0x95, 0x6f, 0x9c, 0xed, 0x97, 0x6f, 0xc7, 0xed, 0x7f,
    0xf9, 0x10, 0x01, 0xc1, 0xa8, 0x30, 0xde, 0xb1
]

# Convert the uint8_t array to a byte array
private_key_bytes = bytes(get_ec_random)

# Convert the byte array to an integer
private_key_int = int.from_bytes(private_key_bytes, byteorder='big')

# Create the private key object
private_key = ec.derive_private_key(private_key_int, ec.SECP256K1(), default_backend())

# Print the private key to confirm (in PEM format)
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

print(private_key_pem.decode('utf-8'))

# private_key = ec.generate_private_key(ec.SECP256K1(), default_backend()) # when new key to give
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()

# Get the private key in integer form
private_numbers = private_key.private_numbers()
private_value = private_numbers.private_value

# Convert the integer to a byte array (32 bytes for secp256k1)
private_key_bytes = private_value.to_bytes(32, byteorder='big')
# Print the byte array in uint8 format
print("uint8_t private_key_bytes[32] = {", end="")
print(", ".join(f"\"0x{byte:02x}\"" for byte in private_key_bytes), end="")
print(" };")

print("private_key:", private_key_bytes.hex())

cp = ellipticcurve.Point(curve, public_numbers.x, public_numbers.y)
compressed = compress_coords(cp)
print(f"Compressed_public_key: {compressed.hex()}")

uncompressed_point = uncompress_coords(curve, compressed)
# print(f"Uncompressed public key int: ({uncompressed_point.x()}, {uncompressed_point.y()})")
print("Uncompressed_public_key:", format(uncompressed_point.x(), '064x'), format(uncompressed_point.y(), '064x'))

