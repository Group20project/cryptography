from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP

# AES Encryption/Decryption Functions
def aes_encrypt(plain_text, aes_key):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plain_text)
    return cipher.nonce, ciphertext, tag

def aes_decrypt(nonce, ciphertext, tag, aes_key):
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# RSA Encryption/Decryption for AES Key
def rsa_encrypt(aes_key, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key

def rsa_decrypt(encrypted_key, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_key = cipher_rsa.decrypt(encrypted_key)
    return decrypted_key

# Digital Signature Generation and Verification
def sign_data(private_key, data):
    h = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(public_key, data, signature):
    h = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Generate RSA keys for signing and encryption
def generate_rsa_keys():
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    return private_key, public_key

# Main Flow
if __name__ == "__main__":
    # Step 1: AES Key and Message
    message = b"Secret message that needs encryption!"
    aes_key = get_random_bytes(32)  # AES-256

    # Step 2: Encrypt message with AES
    nonce, ciphertext, tag = aes_encrypt(message, aes_key)

    # Step 3: Generate RSA key pair for encryption and signing
    rsa_private_key, rsa_public_key = generate_rsa_keys()

    # Step 4: Encrypt AES key using RSA
    encrypted_aes_key = rsa_encrypt(aes_key, rsa_public_key)

    # Step 5: Sign the encrypted AES key and ciphertext
    signature = sign_data(rsa_private_key, encrypted_aes_key + ciphertext)

    # Transmission: send (encrypted_aes_key, ciphertext, tag, nonce, signature)

    # ========== Receiver Side ==========

    # Step 6: Verify the signature
    if verify_signature(rsa_public_key, encrypted_aes_key + ciphertext, signature):
        print("Signature verified successfully!")

        # Step 7: Decrypt the AES key using RSA
        decrypted_aes_key = rsa_decrypt(encrypted_aes_key, rsa_private_key)

        # Step 8: Decrypt the message using AES
        decrypted_message = aes_decrypt(nonce, ciphertext, tag, decrypted_aes_key)
        print("PlainText:", message)
        print("aes_key:", aes_key)
        print("CipherText:", ciphertext)
        print("Decrypted message:", decrypted_message.decode())
    else:
        print("Signature verification failed!")
