"""
shield_agent.py
================
"Shield Agent" — Amélioration B du projet.

Dès qu'un nouveau bloc de Threat Intelligence est validé et ajouté à la
blockchain locale d'un nœud, cet agent :
  1. extrait automatiquement les indicateurs de compromission (IOCs),
  2. vérifie la signature de l'émetteur (double contrôle défensif),
  3. met à jour un "pare-feu" simulé (fichier texte listant les IP bloquées),
  4. journalise l'action avec un horodatage précis (démonstration < 10 s).

Dans un déploiement réel, l'étape 3 appellerait iptables / un firewall
matériel. Ici, elle est simulée par un fichier `firewall_<node_id>.txt`
afin de rester portable et sans droits root.
"""

import os
import time

from crypto_utils import verify_signature


class ShieldAgent:
    def __init__(self, node_id: str, public_keys: dict, firewall_dir: str):
        self.node_id = node_id
        self.public_keys = public_keys  # node_id -> objet clé publique chargé
        self.blocked_ips = set()
        self.log = []

        os.makedirs(firewall_dir, exist_ok=True)
        self.firewall_path = os.path.join(firewall_dir, f"firewall_{node_id}.txt")
        if not os.path.exists(self.firewall_path):
            with open(self.firewall_path, "w") as f:
                f.write("# Règles de filtrage simulées - The Shield CTI\n")

    def process_block(self, block: dict):
        """Analyse un bloc fraîchement committé et réagit aux IOCs qu'il contient."""
        actions = []
        for tx in block["transactions"]:
            if tx.get("tx_type") == "vault_deposit":
                # Simple traçabilité : aucune action pare-feu pour un dépôt de données.
                print(
                    f"[VAULT:{self.node_id}] Preuve d'intégrité ancrée "
                    f"(bloc #{block['index']}, hash={tx.get('data_hash', '')[:16]}...)"
                )
                continue

            if tx.get("ioc_type") != "ip":
                continue

            emitter = tx["node_id"]
            pubkey = self.public_keys.get(emitter)
            message = tx["signed_payload"]
            signature_ok = bool(pubkey) and verify_signature(pubkey, message, tx["signature"])

            if not signature_ok:
                # Sécurité en profondeur : même si le bloc a été committé,
                # l'agent revérifie localement avant d'agir.
                continue

            ip = tx["value"]
            if ip in self.blocked_ips:
                continue

            t0 = tx.get("detected_at", block["timestamp"])
            t_block = time.time()
            latency = round(t_block - t0, 3)

            self.blocked_ips.add(ip)
            with open(self.firewall_path, "a") as f:
                f.write(f"DROP {ip}  # source={emitter} bloc={block['index']} latence={latency}s\n")

            entry = {
                "ip": ip,
                "source_node": emitter,
                "block_index": block["index"],
                "latency_seconds": latency,
                "blocked_at": t_block,
            }
            self.log.append(entry)
            actions.append(entry)
            print(
                f"[SHIELD AGENT:{self.node_id}] IP {ip} bloquée automatiquement "
                f"(émise par {emitter}, bloc #{block['index']}, latence {latency}s)"
            )
        return actions

    def status(self):
        return {
            "node_id": self.node_id,
            "blocked_ips": sorted(self.blocked_ips),
            "log": self.log,
        }
