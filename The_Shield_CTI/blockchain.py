"""
blockchain.py
=============
Registre de Threat Intelligence décentralisé.

Consensus : "Proof of Reputation" (PoR) — Amélioration A du projet.
Le pouvoir de valider un bloc dépend du poids de réputation du nœud
(ex : DGSSI = 10, Banques/Institutions = 8, PME = 3). Un bloc n'est
committé que si les nœuds qui l'approuvent représentent au moins
`MIN_APPROVAL_RATIO` du poids total du réseau. Un nœud qui tente
d'injecter une fausse alerte voit sa réputation s'effondrer (slashing).
"""

import time
import json

from crypto_utils import sha256_hex


class Block:
    def __init__(self, index, timestamp, transactions, previous_hash, validator,
                 validator_signature=""):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions          # liste de "Threat Advisories"
        self.previous_hash = previous_hash
        self.validator = validator                # nœud proposeur du bloc
        self.validator_signature = validator_signature
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        block_string = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "transactions": self.transactions,
                "previous_hash": self.previous_hash,
                "validator": self.validator,
            },
            sort_keys=True,
        )
        return sha256_hex(block_string)

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "validator": self.validator,
            "validator_signature": self.validator_signature,
            "hash": self.hash,
        }

    @staticmethod
    def from_dict(d: dict) -> "Block":
        b = Block(
            d["index"], d["timestamp"], d["transactions"],
            d["previous_hash"], d["validator"], d.get("validator_signature", ""),
        )
        b.hash = d["hash"]
        return b


class Blockchain:
    MIN_APPROVAL_RATIO = 0.51  # majorité pondérée par réputation requise

    def __init__(self, reputations: dict):
        self.chain = []
        self.pending_transactions = []
        self.reputations = dict(reputations)  # node_id -> poids de réputation
        self._create_genesis_block()

    def _create_genesis_block(self):
        # Timestamp fixe et déterministe : tous les nœuds doivent démarrer
        # avec un bloc genesis strictement identique (même hash), sans quoi
        # le contrôle de chaînage previous_hash échouerait entre eux.
        genesis = Block(0, 0.0, [], "0" * 64, "GENESIS")
        self.chain.append(genesis)

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    def total_reputation(self) -> float:
        return sum(self.reputations.values())

    def add_pending_transaction(self, tx: dict):
        self.pending_transactions.append(tx)

    def propose_block(self, proposer_id: str):
        """Le nœud à l'origine de la détection construit un bloc candidat."""
        if not self.pending_transactions:
            return None
        return Block(
            index=len(self.chain),
            timestamp=time.time(),
            transactions=self.pending_transactions.copy(),
            previous_hash=self.last_block.hash,
            validator=proposer_id,
        )

    def compute_approval_weight(self, votes: dict) -> float:
        """votes : {node_id: bool} -> poids cumulé des nœuds qui approuvent."""
        return sum(self.reputations.get(nid, 0) for nid, ok in votes.items() if ok)

    def is_block_approved(self, votes: dict) -> bool:
        approved_weight = self.compute_approval_weight(votes)
        return approved_weight >= self.MIN_APPROVAL_RATIO * self.total_reputation()

    def commit_block(self, block: "Block"):
        self.chain.append(block)
        committed_ids = {tx["tx_id"] for tx in block.transactions}
        self.pending_transactions = [
            tx for tx in self.pending_transactions if tx["tx_id"] not in committed_ids
        ]

    def slash_reputation(self, node_id: str, penalty: int = 5):
        """Sanction appliquée à un nœud qui a tenté d'injecter une fausse alerte."""
        if node_id in self.reputations:
            self.reputations[node_id] = max(0, self.reputations[node_id] - penalty)

    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current, previous = self.chain[i], self.chain[i - 1]
            if current.previous_hash != previous.hash:
                return False
            if current.hash != current.compute_hash():
                return False
        return True

    def to_list(self):
        return [b.to_dict() for b in self.chain]
