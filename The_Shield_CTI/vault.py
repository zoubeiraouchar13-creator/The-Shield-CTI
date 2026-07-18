"""
vault.py
========
Coffre-fort de données personnelles chiffrées par institution ("Data Vault").

Permet à chaque institution d'introduire des données sensibles (nom, prénom,
numéro de carte d'identité, etc.), de les CHIFFRER AVANT tout ancrage sur la
blockchain, puis de publier une preuve d'intégrité (hash + clé AES chiffrée
pour le régulateur) sous forme de transaction "vault_deposit", validée par
le même consensus Proof of Reputation que les Threat Advisories.

Principe (chiffrement hybride, cohérent avec le reste du projet) :
  1. Les données sont sérialisées en JSON canonique.
  2. Une clé AES-256 aléatoire est générée pour CE dépôt et chiffre les
     données (AES-GCM, chiffrement authentifié).
  3. La clé AES est elle-même chiffrée avec la clé publique du régulateur
     (RSA-OAEP) : seul le régulateur (maCERT/DGSSI) pourrait la déchiffrer,
     dans un cadre d'audit légal encadré.
  4. Seuls le HASH SHA-256 des données en clair et la clé AES chiffrée pour
     le régulateur sont ancrés sur la blockchain — preuve d'intégrité et
     d'horodatage vérifiable par tout le réseau, SANS jamais exposer la
     donnée elle-même publiquement.
  5. Le texte chiffré complet et la clé AES en clair restent stockés
     localement, uniquement chez l'institution propriétaire de la donnée.
     Même le régulateur ne peut rien déchiffrer sans que l'institution ne
     lui transmette aussi le texte chiffré (séparation des pouvoirs).
"""

import json
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_utils import encrypt_for_regulator, sha256_hex


def mask_value(value) -> str:
    value = str(value)
    if len(value) <= 2:
        return "*" * len(value)
    return value[0] + "*" * (len(value) - 2) + value[-1]


def mask_record(record: dict) -> dict:
    return {k: mask_value(v) for k, v in record.items()}


class VaultStore:
    """
    Coffre-fort LOCAL d'une institution.
    Rien de son contenu (ciphertext, clé AES en clair) n'est jamais transmis
    au réseau : seule une preuve d'intégrité l'est (cf. encrypt_record).
    """

    def __init__(self, node_id: str):
        self.node_id = node_id
        self.entries = {}  # tx_id -> détails privés + méta

    def encrypt_record(self, record: dict, regulator_public_key):
        """
        Chiffre un enregistrement.
        Retourne (public_material, private_material) :
        - public_material : ce qui sera ancré sur la blockchain
          (data_hash, clé AES chiffrée pour le régulateur, liste des champs).
        - private_material : ce qui reste STRICTEMENT local
          (ciphertext, nonce, clé AES en clair, aperçu masqué pour la GUI).
        """
        plaintext_json = json.dumps(record, sort_keys=True)
        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext_json.encode(), None)

        data_hash = sha256_hex(plaintext_json)
        encrypted_key_for_regulator = encrypt_for_regulator(regulator_public_key, aes_key.hex())

        public_material = {
            "data_hash": data_hash,
            "encrypted_key_for_regulator": encrypted_key_for_regulator,
            "fields": sorted(record.keys()),
        }
        private_material = {
            "ciphertext": ciphertext.hex(),
            "nonce": nonce.hex(),
            "aes_key": aes_key.hex(),
            "masked": mask_record(record),
        }
        return public_material, private_material

    def store(self, tx_id: str, private_material: dict, public_material: dict):
        self.entries[tx_id] = {
            **private_material,
            "data_hash": public_material["data_hash"],
            "fields": public_material["fields"],
            "block_index": None,
            "stored_at": time.time(),
        }

    def mark_committed(self, tx_id: str, block_index: int):
        if tx_id in self.entries:
            self.entries[tx_id]["block_index"] = block_index

    def list_entries(self):
        out = [
            {
                "tx_id": tx_id,
                "masked": e["masked"],
                "fields": e["fields"],
                "data_hash": e["data_hash"],
                "block_index": e["block_index"],
                "stored_at": e["stored_at"],
            }
            for tx_id, e in self.entries.items()
        ]
        return sorted(out, key=lambda x: x["stored_at"])
