from Crypto.Cipher import DES

# Create standard DES cipher
ref = DES.new(
    bytes.fromhex('133457799BBCDFF1'),
    DES.MODE_ECB
)

# Encrypt one 8-byte plaintext block
ciphertext = ref.encrypt(bytes.fromhex('0123456789ABCDEF'))

print(ciphertext.hex().upper())