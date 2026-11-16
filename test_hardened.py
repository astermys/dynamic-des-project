from pathlib import Path
from ddes.hardened import HardenedDES

des = HardenedDES.from_hex('133457799BBCDFF1', 'CAB3')

MAC = b'independent MAC key'

plain = Path('plain.txt').read_bytes()

Path('secret.bin').write_bytes(des.seal(plain, MAC))

restored = des.open(Path('secret.bin').read_bytes(), MAC)

Path('restored.txt').write_bytes(restored)

print("Encryption successful!")
print("Decryption successful!")
print("Original and restored files match:", plain == restored)