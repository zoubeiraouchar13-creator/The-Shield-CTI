"""
node_app.py
===========
Nœud SOC du réseau The Shield CTI (ex : CNSS, ANCFCC, DGSSI, ...).

Lancement :
    python node_app.py <NODE_ID>

Chaque nœud :
  - possède sa propre copie de la blockchain,
  - signe ses propres alertes (Threat Advisories) avec sa clé privée,
  - diffuse ses transactions aux autres nœuds,
  - propose et vote les blocs selon le consensus Proof of Reputation,
  - héberge son propre Shield Agent qui réagit aux blocs committés.
"""

import csv
import io
import json
import os
import sys
import time
import uuid

import requests
from flask import Flask, jsonify, render_template_string, request

from blockchain import Block, Blockchain
from crypto_utils import (
    encrypt_for_regulator,
    load_private_key_from_pem,
    load_public_key_from_pem,
    sha256_hex,
    sign_message,
    verify_signature,
)
from shield_agent import ShieldAgent
from vault import VaultStore

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, "keys")
FIREWALL_DIR = os.path.join(BASE_DIR, "firewall_rules")

REQUEST_TIMEOUT = 3  # secondes, pour ne pas bloquer la démo si un nœud est down

STYLE = """
<style>
  body { font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color:#1a1a2e;}
  h1 { color:#0f3460; }
  .card { background:#f5f6fa; border:1px solid #dcdde1; border-radius:10px; padding:1.2rem; margin-bottom:1.5rem;}
  input[type=text] { padding:.4rem; margin:.2rem 0; width:100%; box-sizing:border-box;}
  label { font-weight:600; font-size:.85rem; display:block; margin-top:.5rem;}
  button { background:#0f3460; color:white; border:none; padding:.5rem 1.2rem; border-radius:6px; cursor:pointer; margin-top:.8rem;}
  table { width:100%; border-collapse: collapse; font-size:.85rem;}
  th, td { border-bottom:1px solid #dcdde1; text-align:left; padding:.4rem;}
  .badge { background:#16c79a; color:white; padding:.1rem .5rem; border-radius:12px; font-size:.75rem;}
  .badge.pending { background:#e94560; }
  nav a { margin-right:1rem; font-size:.85rem; }
  code { background:#eee; padding:.1rem .3rem; border-radius:4px; }
</style>
"""

NAV = """
<nav>
  <a href="/">Accueil</a>
  <a href="/vault/ui">Coffre-fort</a>
  <a href="/chain">Blockchain (JSON)</a>
  <a href="/reputation">Réputation (JSON)</a>
  <a href="/firewall">Pare-feu (JSON)</a>
</nav>
"""

HOME_HTML = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>The Shield CTI — {{ node_id }}</title>""" + STYLE + """</head><body>""" + NAV + """
<h1>🛡️ Nœud {{ node_id }} <small>({{ role }})</small></h1>
<div class="card">
  <p><strong>Longueur de la blockchain :</strong> {{ chain_length }} bloc(s)</p>
  <p><strong>Enregistrements dans le coffre-fort local :</strong> {{ vault_count }}</p>
  <p><strong>Table de réputation du réseau :</strong></p>
  <ul>
  {% for nid, w in reputation.items() %}<li>{{ nid }} : {{ w }}</li>{% endfor %}
  </ul>
</div>
<div class="card">
  <p>👉 Rendez-vous sur <a href="/vault/ui">le coffre-fort</a> pour introduire des données
  (formulaire ou import CSV) : elles seront chiffrées <strong>avant</strong> tout ancrage sur la blockchain.</p>
</div>
</body></html>
"""

VAULT_HTML = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Coffre-fort — {{ node_id }}</title>""" + STYLE + """</head><body>""" + NAV + """
<h1>🔐 Coffre-fort de données — {{ node_id }} <small>({{ role }})</small></h1>
<p>Les données saisies ici sont <strong>chiffrées localement (AES-256-GCM)</strong> avant tout envoi.
Seuls un <strong>hash d'intégrité</strong> et une <strong>clé de secours chiffrée pour le régulateur (DGSSI)</strong>
sont ancrés sur la blockchain via le consensus Proof of Reputation. Les données en clair et la clé AES
ne quittent jamais ce nœud.</p>

<div class="card">
  <h3>➕ Ajouter un enregistrement</h3>
  <form id="recordForm">
    <label>Nom</label><input type="text" name="nom" required>
    <label>Prénom</label><input type="text" name="prenom" required>
    <label>Carte d'identité (CIN)</label><input type="text" name="cin" required>
    <label>Téléphone (optionnel)</label><input type="text" name="telephone">
    <button type="submit">Chiffrer et ancrer sur la blockchain</button>
  </form>
  <p id="recordStatus"></p>
</div>

<div class="card">
  <h3>📄 Importer un fichier CSV</h3>
  <p>Colonnes libres, ex : <code>nom,prenom,cin,telephone</code></p>
  <form id="csvForm">
    <input type="file" name="file" accept=".csv" required>
    <button type="submit">Chiffrer et ancrer le fichier</button>
  </form>
  <p id="csvStatus"></p>
</div>

<div class="card">
  <h3>🗄️ Enregistrements stockés localement (valeurs masquées)</h3>
  <table id="vaultTable">
    <thead><tr><th>Champs</th><th>Aperçu masqué</th><th>Hash d'intégrité</th><th>Statut</th></tr></thead>
    <tbody></tbody>
  </table>
</div>

<script>
async function refreshVault() {
  const res = await fetch('/vault');
  const entries = await res.json();
  const tbody = document.querySelector('#vaultTable tbody');
  tbody.innerHTML = '';
  entries.forEach(e => {
    const tr = document.createElement('tr');
    const status = e.block_index !== null
      ? `<span class="badge">bloc #${e.block_index}</span>`
      : `<span class="badge pending">en attente</span>`;
    tr.innerHTML = `<td>${e.fields.join(', ')}</td>
                    <td>${JSON.stringify(e.masked)}</td>
                    <td><code>${e.data_hash.slice(0,16)}...</code></td>
                    <td>${status}</td>`;
    tbody.appendChild(tr);
  });
}

document.getElementById('recordForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const form = new FormData(ev.target);
  const record = {};
  form.forEach((v, k) => { if (v) record[k] = v; });
  document.getElementById('recordStatus').textContent = 'Chiffrement et consensus en cours...';
  const res = await fetch('/vault/record', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(record)
  });
  const data = await res.json();
  document.getElementById('recordStatus').textContent =
    (data.propose_result && data.propose_result.status === 'committed')
      ? `✅ Ancré dans le bloc #${data.propose_result.block_index}`
      : `⚠️ ${JSON.stringify(data.propose_result || data)}`;
  ev.target.reset();
  refreshVault();
});

document.getElementById('csvForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const form = new FormData(ev.target);
  document.getElementById('csvStatus').textContent = 'Import en cours...';
  const res = await fetch('/vault/upload_csv', { method: 'POST', body: form });
  const data = await res.json();
  document.getElementById('csvStatus').textContent =
    `✅ ${data.records_ingested} enregistrement(s) chiffré(s) et ancré(s)`;
  ev.target.reset();
  refreshVault();
});

refreshVault();
</script>
</body></html>
"""


def load_network():
    with open(os.path.join(BASE_DIR, "network_config.json")) as f:
        net = json.load(f)
    with open(os.path.join(BASE_DIR, "public_keys.json")) as f:
        pub_pems = json.load(f)
    return net, pub_pems


def create_app(node_id: str):
    net, pub_pems = load_network()
    if node_id not in net["nodes"]:
        raise ValueError(f"Nœud inconnu : {node_id}")

    my_config = net["nodes"][node_id]
    reputations = {nid: cfg["reputation"] for nid, cfg in net["nodes"].items()}
    peers = {
        nid: f"http://127.0.0.1:{cfg['port']}"
        for nid, cfg in net["nodes"].items()
        if nid != node_id
    }

    with open(os.path.join(KEYS_DIR, f"{node_id}_private.pem")) as f:
        private_key = load_private_key_from_pem(f.read())

    public_keys = {nid: load_public_key_from_pem(pem) for nid, pem in pub_pems.items()}
    regulator_public_key = public_keys[net["regulator_id"]]

    chain = Blockchain(reputations)
    agent = ShieldAgent(node_id, public_keys, FIREWALL_DIR)
    vault = VaultStore(node_id)

    app = Flask(f"node-{node_id}")
    app.config["JSON_SORT_KEYS"] = False

    # ------------------------------------------------------------------
    # Etat / diagnostic
    # ------------------------------------------------------------------

    @app.get("/status")
    def status():
        return jsonify(
            {
                "node_id": node_id,
                "role": my_config["role"],
                "reputation_table": chain.reputations,
                "chain_length": len(chain.chain),
                "pending_transactions": len(chain.pending_transactions),
            }
        )

    @app.get("/chain")
    def get_chain():
        return jsonify(chain.to_list())

    @app.get("/reputation")
    def get_reputation():
        return jsonify(chain.reputations)

    @app.get("/firewall")
    def get_firewall():
        return jsonify(agent.status())

    # ------------------------------------------------------------------
    # Tableau de bord HTML (page d'accueil du nœud)
    # ------------------------------------------------------------------

    @app.get("/")
    def home():
        return render_template_string(
            HOME_HTML,
            node_id=node_id,
            role=my_config["role"],
            reputation=chain.reputations,
            chain_length=len(chain.chain),
            vault_count=len(vault.entries),
        )

    # ------------------------------------------------------------------
    # Coffre-fort de données (Data Vault) : chiffrement AVANT ancrage
    # ------------------------------------------------------------------

    def _ingest_record(record: dict):
        """Chiffre un enregistrement, l'ancre sur la blockchain (preuve
        d'intégrité) via le consensus PoR, puis marque son statut local."""
        public_material, private_material = vault.encrypt_record(record, regulator_public_key)
        tx, tx_id = _build_and_sign("vault_deposit", public_material)
        vault.store(tx_id, private_material, public_material)

        chain.add_pending_transaction(tx)
        _broadcast_transaction(tx)
        result = _propose_and_commit()
        if result.get("status") == "committed":
            vault.mark_committed(tx_id, result["block_index"])
        return tx_id, result

    @app.get("/vault")
    def vault_list():
        return jsonify(vault.list_entries())

    @app.post("/vault/record")
    def vault_add_record():
        """
        Body JSON attendu, ex :
        {"nom": "Alaoui", "prenom": "Sara", "cin": "AB123456", "telephone": "06..."}
        """
        record = {k: v for k, v in (request.get_json(force=True) or {}).items() if v}
        if not record:
            return jsonify({"error": "aucun champ fourni"}), 400
        tx_id, result = _ingest_record(record)
        return jsonify({"tx_id": tx_id, "propose_result": result}), 201

    @app.post("/vault/upload_csv")
    def vault_upload_csv():
        """Importe un fichier CSV (multipart/form-data, champ 'file') :
        une ligne = un enregistrement chiffré individuellement, tous ancrés
        dans un même bloc à la fin de l'import."""
        if "file" not in request.files:
            return jsonify({"error": "fichier manquant (champ 'file')"}), 400

        content = request.files["file"].read().decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(content))

        tx_ids = []
        for row in reader:
            record = {k.strip(): v.strip() for k, v in row.items() if k and v}
            if not record:
                continue
            public_material, private_material = vault.encrypt_record(record, regulator_public_key)
            tx, tx_id = _build_and_sign("vault_deposit", public_material)
            vault.store(tx_id, private_material, public_material)
            chain.add_pending_transaction(tx)
            _broadcast_transaction(tx)
            tx_ids.append(tx_id)

        result = _propose_and_commit()  # un seul bloc pour tout le fichier
        if result.get("status") == "committed":
            for tx_id in tx_ids:
                vault.mark_committed(tx_id, result["block_index"])

        return jsonify(
            {"records_ingested": len(tx_ids), "tx_ids": tx_ids, "propose_result": result}
        ), 201

    @app.get("/vault/ui")
    def vault_ui():
        return render_template_string(VAULT_HTML, node_id=node_id, role=my_config["role"])

    # ------------------------------------------------------------------
    # Soumission d'une alerte (Threat Advisory) par ce nœud
    # ------------------------------------------------------------------

    @app.post("/advisory")
    def submit_advisory():
        """
        Body JSON attendu :
        {
          "ioc_type": "ip" | "hash",
          "value": "185.220.101.7",
          "severity": "high",
          "sensitive": false,
          "_forge_invalid_signature": false   # réservé aux tests de fraude
        }
        """
        data = request.get_json(force=True)
        ioc_type = data["ioc_type"]
        value = data["value"]
        severity = data.get("severity", "medium")
        sensitive = data.get("sensitive", False)
        forge_invalid = data.get("_forge_invalid_signature", False)

        detected_at = time.time()
        tx_id = uuid.uuid4().hex

        # Le contenu public de la transaction (ce que le réseau peut valider)
        public_value = sha256_hex(value) if sensitive else value

        payload = {
            "tx_id": tx_id,
            "node_id": node_id,
            "tx_type": "threat_advisory",
            "ioc_type": ioc_type,
            "value": public_value,
            "severity": severity,
            "detected_at": detected_at,
        }
        signed_payload = json.dumps(payload, sort_keys=True)
        signature = sign_message(private_key, signed_payload)

        if forge_invalid:
            # Simule un nœud malveillant qui falsifie la transaction après signature
            # (utilisé pour démontrer le mécanisme de slashing de réputation).
            payload["value"] = "FORGED-" + str(public_value)
            signed_payload = json.dumps(payload, sort_keys=True)  # ne correspond plus à `signature`

        tx = {
            **payload,
            "signed_payload": signed_payload,
            "signature": signature,
        }

        if sensitive:
            tx["encrypted_detail"] = encrypt_for_regulator(regulator_public_key, value)
            tx["value"] = public_value  # seul le hash circule publiquement

        chain.add_pending_transaction(tx)
        _broadcast_transaction(tx)

        # Le nœud à l'origine de la détection propose immédiatement le bloc
        result = _propose_and_commit()

        return jsonify({"tx_id": tx_id, "propose_result": result}), 201

    # ------------------------------------------------------------------
    # Réception d'une transaction diffusée par un pair
    # ------------------------------------------------------------------

    @app.post("/transaction/receive")
    def receive_transaction():
        tx = request.get_json(force=True)
        emitter = tx["node_id"]
        pubkey = public_keys.get(emitter)

        valid = bool(pubkey) and verify_signature(pubkey, tx["signed_payload"], tx["signature"])
        if not valid:
            # Tentative d'injection d'une fausse alerte -> sanction immédiate
            chain.slash_reputation(emitter)
            return jsonify({"accepted": False, "reason": "signature invalide"}), 400

        # Evite les doublons
        if not any(existing["tx_id"] == tx["tx_id"] for existing in chain.pending_transactions):
            chain.add_pending_transaction(tx)
        return jsonify({"accepted": True}), 200

    # ------------------------------------------------------------------
    # Vote de validation d'un bloc candidat (consensus PoR)
    # ------------------------------------------------------------------

    @app.post("/block/vote")
    def vote_block():
        block_dict = request.get_json(force=True)

        # 1) Le bloc doit s'enchaîner correctement sur la dernière chaîne connue
        if block_dict["previous_hash"] != chain.last_block.hash:
            return jsonify({"approve": False, "reason": "previous_hash incorrect"})

        # 2) Le hash du bloc doit être cohérent avec son contenu
        candidate = Block.from_dict(block_dict)
        if candidate.hash != candidate.compute_hash():
            return jsonify({"approve": False, "reason": "hash incohérent"})

        # 3) Chaque transaction doit être signée valablement par son émetteur
        for tx in block_dict["transactions"]:
            pubkey = public_keys.get(tx["node_id"])
            if not pubkey or not verify_signature(pubkey, tx["signed_payload"], tx["signature"]):
                chain.slash_reputation(tx["node_id"])
                return jsonify({"approve": False, "reason": f"transaction invalide de {tx['node_id']}"})

        return jsonify({"approve": True})

    # ------------------------------------------------------------------
    # Réception d'un bloc committé par le proposeur
    # ------------------------------------------------------------------

    @app.post("/block/commit")
    def commit_block_route():
        payload = request.get_json(force=True)
        block = Block.from_dict(payload["block"])

        if block.previous_hash == chain.last_block.hash:
            chain.commit_block(block)
            # Synchronise la table de réputation (slashing éventuel inclus)
            for nid, rep in payload.get("reputations", {}).items():
                chain.reputations[nid] = rep
            actions = agent.process_block(block.to_dict())
            return jsonify({"committed": True, "shield_actions": actions})

        return jsonify({"committed": False, "reason": "chaîne désynchronisée"}), 409

    # ------------------------------------------------------------------
    # Logique interne : diffusion + consensus
    # ------------------------------------------------------------------

    def _build_and_sign(tx_type: str, public_fields: dict):
        """Construit et signe une transaction générique (utilisée par le
        coffre-fort ; les Threat Advisories ont leur propre construction
        dédiée dans /advisory pour gérer le cas 'sensitive')."""
        tx_id = uuid.uuid4().hex
        payload = {
            "tx_id": tx_id,
            "node_id": node_id,
            "tx_type": tx_type,
            "timestamp": time.time(),
            **public_fields,
        }
        signed_payload = json.dumps(payload, sort_keys=True)
        signature = sign_message(private_key, signed_payload)
        tx = {**payload, "signed_payload": signed_payload, "signature": signature}
        return tx, tx_id

    def _broadcast_transaction(tx: dict):
        for peer_url in peers.values():
            try:
                requests.post(f"{peer_url}/transaction/receive", json=tx, timeout=REQUEST_TIMEOUT)
            except requests.exceptions.RequestException:
                pass  # nœud injoignable : tolérant aux pannes pour la démo

    def _propose_and_commit():
        block = chain.propose_block(proposer_id=node_id)
        if block is None:
            return {"status": "no_pending_transactions"}

        votes = {node_id: True}  # le proposeur s'auto-approuve (il a vérifié ses propres tx)
        for peer_id, peer_url in peers.items():
            try:
                resp = requests.post(
                    f"{peer_url}/block/vote", json=block.to_dict(), timeout=REQUEST_TIMEOUT
                )
                votes[peer_id] = bool(resp.json().get("approve", False))
            except requests.exceptions.RequestException:
                votes[peer_id] = False  # nœud injoignable = abstention

        if not chain.is_block_approved(votes):
            return {"status": "rejected", "votes": votes,
                    "approved_weight": chain.compute_approval_weight(votes),
                    "required_weight": chain.MIN_APPROVAL_RATIO * chain.total_reputation()}

        chain.commit_block(block)
        shield_actions = agent.process_block(block.to_dict())

        # Diffusion du bloc committé + table de réputation à jour (ex: slashing)
        commit_payload = {"block": block.to_dict(), "reputations": chain.reputations}
        for peer_url in peers.values():
            try:
                requests.post(f"{peer_url}/block/commit", json=commit_payload, timeout=REQUEST_TIMEOUT)
            except requests.exceptions.RequestException:
                pass

        return {"status": "committed", "block_index": block.index,
                "votes": votes, "shield_actions": shield_actions}

    return app


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python node_app.py <NODE_ID>")
        sys.exit(1)

    node_id_arg = sys.argv[1]
    net_cfg, _ = load_network()
    port = net_cfg["nodes"][node_id_arg]["port"]

    flask_app = create_app(node_id_arg)
    print(f"[node_app] Démarrage du nœud {node_id_arg} sur le port {port}")
    flask_app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
