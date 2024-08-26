from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from binascii import unhexlify


def hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(input_key_material)
    return h.finalize()


def hkdf_expand_label(secret, label, length):
    hkdf_expand = HKDFExpand(algorithm=hashes.SHA256(),
                             length=length, info=label, backend=None)
    return hkdf_expand.derive(secret)


def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=None)
    encryptor = cipher.encryptor()

    # Add padding to make the plaintext a multiple of the AES block size (16 bytes)
    padder = PKCS7(128).padder()
    plaintext_padded = padder.update(plaintext) + padder.finalize()

    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()
    return ciphertext


def aes_gcm_encrypt(nonce, payload, header, key):
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, payload, header)


quic_salt = unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
quic_salt_v2 = unhexlify("0dede3def700a6db819381be6e269dcbf9bd2ed9")
client_in = unhexlify("00200f746c73313320636c69656e7420696e00")
server_in = unhexlify("00200f746c7331332073657276657220696e00")
quic_key = unhexlify("00100e746c7331332071756963206b657900")
quic_key_v2 = unhexlify("001010746c73313320717569637632206b657900")
quic_iv = unhexlify("000c0d746c733133207175696320697600")
quic_iv_v2 = unhexlify("000c0f746c7331332071756963763220697600")
quic_hp = unhexlify("00100d746c733133207175696320687000")
quic_hp_v2 = unhexlify("00100f746c7331332071756963763220687000")

if __name__ == '__main__':
    i_s = hkdf_extract(quic_salt_v2, unhexlify("8394c8f03e515708"))
    print(i_s.hex())
    cis = hkdf_expand_label(i_s, client_in, 32)
    print(cis.hex())