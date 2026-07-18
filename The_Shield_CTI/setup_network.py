"""
setup_network.py
=================
Initialise le réseau The Shield CTI :
- génère une paire de clés RSA par institution (nœud SOC),
- construit l'annuaire des clés publiques (PKI simplifiée),
- fixe la configuration réseau (port, poids de réputation) de chaque nœud.

À exécuter une seule fois avant de démarrer les nœuds
(ou automatiquement via simulate_attack.py).
"""

import json
import os

from crypto_utils import generate_keypair, private_key_to_pem, public_key_to_pem

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, "keys")

# Institutions participantes et leur poids de réputation initial
# (cf. document de conception : DGSSI = 10, Banques/Institutions = 8, PME = 3)
NODES = {
    "DGSSI":      {"port": 5001, "reputation": 10, "role": "Régulateur (maCERT)"},
    "CNSS":       {"port": 5002, "reputation": 8,  "role": "Institution publique"},
    "ANCFCC":     {"port": 5003, "reputation": 8,  "role": "Institution publique"},
    "BANQUE_X":   {"port": 5004, "reputation": 8,  "role": "Banque"},
    "PME_Y":      {"port": 5005, "reputation": 3,  "role": "PME"},
}

REGULATOR_ID = "DGSSI"  # le maCERT est porté par le nœud DGSSI


def setup():
    os.makedirs(KEYS_DIR, exist_ok=True)
    public_keys = {}

    for node_id in NODES:
        private_key, public_key = generate_keypair()
        priv_pem = private_key_to_pem(private_key)
        pub_pem = public_key_to_pem(public_key)

        with open(os.path.join(KEYS_DIR, f"{node_id}_private.pem"), "w") as f:
            f.write(priv_pem)
        with open(os.path.join(KEYS_DIR, f"{node_id}_public.pem"), "w") as f:
            f.write(pub_pem)

        public_keys[node_id] = pub_pem

    with open(os.path.join(BASE_DIR, "public_keys.json"), "w") as f:
        json.dump(public_keys, f, indent=2)

    network_config = {
        "regulator_id": REGULATOR_ID,
        "nodes": NODES,
    }
    with open(os.path.join(BASE_DIR, "network_config.json"), "w") as f:
        json.dump(network_config, f, indent=2)

    print("[setup_network] Clés RSA générées pour :", ", ".join(NODES.keys()))
    print("[setup_network] Annuaire de clés publiques -> public_keys.json")
    print("[setup_network] Configuration réseau        -> network_config.json")


if __name__ == "__main__":
    setup()
