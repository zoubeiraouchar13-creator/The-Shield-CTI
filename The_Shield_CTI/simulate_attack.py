"""
simulate_attack.py
===================
Scénario de démonstration complet :

  1. Initialise le réseau (clés + configuration) si besoin.
  2. Démarre les 5 nœuds SOC (DGSSI, CNSS, ANCFCC, BANQUE_X, PME_Y).
  3. Le nœud CNSS détecte une IP du hacker et publie une alerte signée.
  4. Le réseau valide la transaction par consensus Proof of Reputation
     et diffuse le bloc committé.
  5. Le Shield Agent du nœud ANCFCC bloque automatiquement la même IP,
     sans intervention humaine, en moins de 10 secondes.
  6. Un nœud PME_Y malveillant tente d'injecter une fausse alerte :
     la transaction est rejetée et sa réputation est sanctionnée.

Usage :
    python simulate_attack.py
"""

import json
import os
import subprocess
import sys
import time

import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON = sys.executable


def ensure_network():
    if not os.path.exists(os.path.join(BASE_DIR, "network_config.json")):
        print("== Initialisation du réseau (génération des clés RSA) ==")
        subprocess.run([PYTHON, os.path.join(BASE_DIR, "setup_network.py")], check=True)
    with open(os.path.join(BASE_DIR, "network_config.json")) as f:
        return json.load(f)


def start_nodes(net_cfg):
    procs = {}
    for node_id in net_cfg["nodes"]:
        proc = subprocess.Popen(
            [PYTHON, os.path.join(BASE_DIR, "node_app.py"), node_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        procs[node_id] = proc
    return procs


def wait_for_nodes(net_cfg, timeout=15):
    deadline = time.time() + timeout
    for node_id, cfg in net_cfg["nodes"].items():
        url = f"http://127.0.0.1:{cfg['port']}/status"
        while time.time() < deadline:
            try:
                r = requests.get(url, timeout=1)
                if r.status_code == 200:
                    break
            except requests.exceptions.RequestException:
                time.sleep(0.3)
        else:
            raise RuntimeError(f"Le nœud {node_id} n'a pas démarré à temps")
    print("== Tous les nœuds sont opérationnels ==\n")


def node_url(net_cfg, node_id):
    return f"http://127.0.0.1:{net_cfg['nodes'][node_id]['port']}"


def print_reputations(net_cfg, node_id="DGSSI"):
    r = requests.get(f"{node_url(net_cfg, node_id)}/reputation", timeout=3)
    print("Table de réputation :", r.json())


def vault_phase(net_cfg):
    print("############################################################")
    print("# PHASE 0 : Dépôt et chiffrement de données AVANT toute attaque")
    print("############################################################")

    # 1) Dépôt manuel côté CNSS (simule la saisie via la GUI /vault/ui)
    record = {"nom": "Alaoui", "prenom": "Sara", "cin": "AB123456", "telephone": "0612345678"}
    print(f"\n[CNSS] Saisie manuelle d'un enregistrement : {record}")
    resp = requests.post(f"{node_url(net_cfg, 'CNSS')}/vault/record", json=record, timeout=10)
    print("Résultat :", json.dumps(resp.json(), indent=2))

    # 2) Import CSV côté ANCFCC (simule un fichier déposé par l'institution)
    csv_path = os.path.join(BASE_DIR, "sample_data", "clients_ancfcc.csv")
    print(f"\n[ANCFCC] Import du fichier CSV : {csv_path}")
    with open(csv_path, "rb") as f:
        resp2 = requests.post(
            f"{node_url(net_cfg, 'ANCFCC')}/vault/upload_csv",
            files={"file": ("clients_ancfcc.csv", f, "text/csv")},
            timeout=15,
        )
    print("Résultat :", json.dumps(resp2.json(), indent=2))

    # 3) Vérification : les données sont bien chiffrées et ancrées, mais
    #    jamais visibles en clair sur le réseau.
    print("\n-- Contenu local (masqué) du coffre-fort CNSS --")
    vault_cnss = requests.get(f"{node_url(net_cfg, 'CNSS')}/vault", timeout=5).json()
    print(json.dumps(vault_cnss, indent=2))

    print("\n-- Ce que la blockchain contient réellement pour ce dépôt (aucune donnée en clair) --")
    chain = requests.get(f"{node_url(net_cfg, 'DGSSI')}/chain", timeout=5).json()
    for b in chain:
        for tx in b["transactions"]:
            if tx.get("tx_type") == "vault_deposit":
                print(f"  Bloc #{b['index']} -> data_hash={tx['data_hash'][:20]}..., "
                      f"clé chiffrée pour DGSSI={tx['encrypted_key_for_regulator'][:20]}...")

    print(
        "\nℹ️  Pour explorer manuellement, ouvrez dans un navigateur :\n"
        f"   CNSS    : {node_url(net_cfg, 'CNSS')}/vault/ui\n"
        f"   ANCFCC  : {node_url(net_cfg, 'ANCFCC')}/vault/ui\n"
        f"   DGSSI   : {node_url(net_cfg, 'DGSSI')}/vault/ui\n"
    )


def scenario(net_cfg):
    attacker_ip = "185.220.101.7"

    print("\n############################################################")
    print("# SCÉNARIO 1 : Attaque The Shield CTI détectée par la CNSS")
    print("############################################################")
    print_reputations(net_cfg)

    t0 = time.time()
    print(f"\n[t=0.0s] Le SOC CNSS détecte l'IP suspecte {attacker_ip} (exfiltration de données)")
    resp = requests.post(
        f"{node_url(net_cfg, 'CNSS')}/advisory",
        json={"ioc_type": "ip", "value": attacker_ip, "severity": "high", "sensitive": False},
        timeout=10,
    )
    print(f"[t={time.time()-t0:.2f}s] Réponse de la CNSS :", json.dumps(resp.json(), indent=2))

    print("\n-- Vérification côté ANCFCC (le bloc a-t-il été reçu et l'IP bloquée ?) --")
    time.sleep(1)  # laisse le temps à la diffusion HTTP locale de se terminer
    firewall = requests.get(f"{node_url(net_cfg, 'ANCFCC')}/firewall", timeout=5).json()
    print(f"[t={time.time()-t0:.2f}s] Firewall ANCFCC :", json.dumps(firewall, indent=2))

    blocked = attacker_ip in firewall.get("blocked_ips", [])
    elapsed = time.time() - t0
    if blocked:
        print(f"\n✅ L'IP {attacker_ip} a été bloquée par l'ANCFCC en {elapsed:.2f} secondes "
              f"(objectif : < 10s) — la riposte est autonome et coordonnée.")
    else:
        print(f"\n⚠️ L'IP n'a pas encore été propagée après {elapsed:.2f}s.")

    print("\n############################################################")
    print("# SCÉNARIO 2 : Une PME tente d'injecter une fausse alerte")
    print("############################################################")
    print_reputations(net_cfg)

    print("\n[PME_Y] Envoi d'une alerte dont la signature ne correspond pas au contenu (fraude)...")
    resp2 = requests.post(
        f"{node_url(net_cfg, 'PME_Y')}/advisory",
        json={
            "ioc_type": "ip",
            "value": "1.2.3.4",
            "severity": "low",
            "sensitive": False,
            "_forge_invalid_signature": True,
        },
        timeout=10,
    )
    print("Résultat de la proposition de bloc :", json.dumps(resp2.json(), indent=2))

    print("\nTable de réputation après tentative de fraude :")
    print_reputations(net_cfg)

    print("\n############################################################")
    print("# SCÉNARIO 3 : État final de la blockchain (nœud DGSSI)")
    print("############################################################")
    chain = requests.get(f"{node_url(net_cfg, 'DGSSI')}/chain", timeout=5).json()
    print(f"Longueur de la chaîne : {len(chain)} bloc(s)")
    for b in chain:
        print(f"  Bloc #{b['index']} | validateur={b['validator']} | "
              f"{len(b['transactions'])} transaction(s) | hash={b['hash'][:16]}...")


def main():
    net_cfg = ensure_network()
    procs = start_nodes(net_cfg)
    try:
        wait_for_nodes(net_cfg)
        vault_phase(net_cfg)
        scenario(net_cfg)
    finally:
        print("\n== Arrêt des nœuds ==")
        for proc in procs.values():
            proc.terminate()
        for proc in procs.values():
            proc.wait(timeout=5)


if __name__ == "__main__":
    main()
