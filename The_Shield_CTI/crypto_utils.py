"""
crypto_utils.py
================
Brique cryptographique de The Shield CTI.

- Signature asymétrique (RSA-PSS / SHA-256) : chaque institution (nœud SOC)
  signe ses "Threat Advisories" avec sa clé privée pour prouver sa légitimité
  sans révéler son identité réelle sur le réseau (clé pseudonyme).
- Chiffrement asymétrique (RSA-OAEP) : réservé aux informations ultra-sensibles
  destinées uniquement au régulateur (maCERT / DGSSI), qui est le seul à
  détenir la clé privée capable de les déchiffrer.
"""

import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# ----------------------------------------------------------------------
# Génération et sérialisation des clés
# ----------------------------------------------------------------------

def generate_keypair():
    """Génère une paire de clés RSA 2048 bits pour un nœud du réseau."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def private_key_to_pem(private_key) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def public_key_to_pem(public_key) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def load_private_key_from_pem(pem_str: str):
    return serialization.load_pem_private_key(pem_str.encode(), password=None)


def load_public_key_from_pem(pem_str: str):
    return serialization.load_pem_public_key(pem_str.encode())


# ----------------------------------------------------------------------
# Hachage
# ----------------------------------------------------------------------

def sha256_hex(data: str) -> str:
    """Empreinte SHA-256 utilisée pour le hash des blocs et des payloads."""
    return hashlib.sha256(data.encode()).hexdigest()


# ----------------------------------------------------------------------
# Signature / vérification (preuve de légitimité de l'émetteur)
# ----------------------------------------------------------------------

def sign_message(private_key, message: str) -> str:
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature.hex()


def verify_signature(public_key, message: str, signature_hex: str) -> bool:
    try:
        public_key.verify(
            bytes.fromhex(signature_hex),
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# ----------------------------------------------------------------------
# Chiffrement réservé au régulateur (maCERT / DGSSI)
# ----------------------------------------------------------------------

def encrypt_for_regulator(public_key, plaintext: str) -> str:
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext.hex()


def decrypt_by_regulator(private_key, ciphertext_hex: str) -> str:
    plaintext = private_key.decrypt(
        bytes.fromhex(ciphertext_hex),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext.decode()
