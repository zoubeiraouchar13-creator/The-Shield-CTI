# The Shield Cybet Threat Intelligence

**Registre de Threat Intelligence Décentralisé & Collaboratif par Agents Autonomes**

Ce projet implémente l'architecture décrite dans le document de conception :
une blockchain souveraine où plusieurs institutions marocaines (SOC) partagent
en temps réel, de manière anonyme mais cryptographiquement vérifiable, des
indicateurs de compromission (IOCs) liés aux Cyber attaques, avec
blocage automatique et coordonné des menaces.

### Les deux améliorations clés

- **Amélioration A — Proof of Reputation (PoR)** : chaque institution a un
  poids de réputation (`DGSSI = 10`, `CNSS/ANCFCC/Banques = 8`, `PME = 3`). Un
  bloc n'est validé que si les nœuds qui l'approuvent représentent plus de 51 %
  du poids total du réseau. Un nœud qui envoie une alerte falsifiée voit sa
  réputation sanctionnée (*slashing*) et perd son pouvoir de validation.
- **Amélioration B — Shield Agent** : dès qu'un bloc est committé, l'agent de
  chaque nœud extrait l'IOC, revérifie la signature, puis met à jour un
  pare-feu simulé (`firewall_rules/firewall_<NODE>.txt`). Une attaque détectée
  chez un institution est bloquée chez les autres en quelques centaines de
  millisecondes.
- **Coffre-fort de données (Data Vault)** : chaque institution dispose d'une
  interface graphique (formulaire + import CSV) pour introduire des données
  personnelles (nom, prénom, CIN, téléphone...). Ces données sont **chiffrées
  localement (AES-256-GCM) avant tout envoi**. Seuls un hash d'intégrité et
  une clé de secours chiffrée pour le régulateur (RSA-OAEP) sont ensuite
  ancrés sur la blockchain via le même consensus PoR — les données en clair
  ne quittent jamais le nœud propriétaire.

---

## 2. Prérequis

- Python 3.12 ou supérieur

Installer les dépendances :

```bash
pip install -r requirements.txt
```

## 3. Démarrage rapide (démonstration automatique)

La façon la plus simple de voir le projet fonctionner : un seul script lance
les 5 nœuds, simule l'attaque, puis affiche le résultat.

### 3.1 Initialiser le réseau (une seule fois)

```bash
python setup_network.py
```
### 3.2 Démarrer les nœuds

Dans 5 terminaux séparés (ou en arrière-plan) :

```bash
python node_app.py DGSSI      # port 5001 - régulateur (maCERT)
python node_app.py CNSS       # port 5002
python node_app.py ANCFCC     # port 5003
python node_app.py BANQUE_X   # port 5004
python node_app.py PME_Y      # port 5005
```
### 3.3 Simuler une Cyber attaque

```bash
python simulate_attack.py
```

Ce script va :

1. Générer les clés RSA et la configuration réseau (si ce n'est pas déjà fait).
2. Démarrer 5 nœuds SOC : `DGSSI`, `CNSS`, `ANCFCC`, `BANQUE_X`, `PME_Y`.
3. **Phase 0 — Coffre-fort** : la CNSS saisit un enregistrement (nom, prénom,
   CIN, téléphone), et l'ANCFCC importe un fichier CSV
   (`sample_data/clients_ancfcc.csv`). Chaque enregistrement est **chiffré
   localement (AES-256-GCM) avant tout envoi**, puis une preuve d'intégrité
   (hash + clé chiffrée pour le régulateur) est ancrée sur la blockchain.
   Le script affiche à la fois le contenu masqué stocké localement et ce que
   la blockchain contient réellement (jamais de donnée en clair).
4. Simuler ensuite la CNSS détectant l'IP `185.220.101.7` (Hacker) et
   publiant une alerte signée.
5. Montrer le consensus Proof of Reputation en action (vote des nœuds,
   commit du bloc).
6. Vérifier que le Shield Agent du nœud **ANCFCC** a bloqué automatiquement
   la même IP en moins de 10 secondes, **sans intervention humaine**.
7. Simuler une **PME malveillante** qui tente d'injecter une fausse alerte :
   la transaction est rejetée et sa réputation est sanctionnée (slashing).
8. Afficher l'état final de la blockchain.
9. Arrêter proprement tous les nœuds.

> Le script arrête les nœuds à la fin pour rendre la démo reproductible.
> Pour explorer les interfaces graphiques (voir section 4 bis), démarrez les
> nœuds manuellement à la place, ou commentez temporairement le bloc
> `finally` de `simulate_attack.py`.

### 3.4 Consulter l'état d'un nœud

```bash
curl http://127.0.0.1:5003/status       # infos générales
curl http://127.0.0.1:5003/chain        # blockchain complète vue par ce nœud
curl http://127.0.0.1:5003/reputation   # table de réputation
curl http://127.0.0.1:5003/firewall     # IP bloquées par le Shield Agent
```

### 4. Les interface graphique :

Sur la page `/vault/ui` de chaque institution, on peut :

- **Saisir manuellement** un enregistrement (nom, prénom, CIN, téléphone) via
  un formulaire — il est chiffré et ancré sur la blockchain en un clic.
- **Importer un fichier CSV** (colonnes libres, ex : `nom,prenom,cin,telephone`)
  — chaque ligne devient un enregistrement chiffré individuellement, tous
  ancrés dans un même bloc. Un exemple est fourni :
  `sample_data/clients_ancfcc.csv`.
- **Visualiser** la table des enregistrements stockés localement, avec les
  valeurs **masquées** (ex : `A****i`) et le hash d'intégrité correspondant,
  ainsi que le numéro du bloc dans lequel la preuve a été ancrée.

**Ce qui est réellement chiffré et où :**

1. Les données sont sérialisées en JSON, puis chiffrées avec une clé AES-256
   aléatoire (AES-GCM, authentifié) — *localement, avant tout envoi réseau*.
2. La clé AES est elle-même chiffrée avec la clé publique du régulateur
   (DGSSI/maCERT) via RSA-OAEP.
3. Seuls le **hash SHA-256** des données en clair et la **clé AES chiffrée
   pour le régulateur** sont ancrés sur la blockchain (transaction de type
   `vault_deposit`), validés par le consensus PoR comme n'importe quelle
   Threat Advisory.
4. Le texte chiffré complet et la clé AES en clair restent **strictement
   locaux** à l'institution propriétaire — même le régulateur ne peut rien
   déchiffrer sans que l'institution ne lui transmette aussi le texte
   chiffré (séparation des pouvoirs, cadre d'audit légal).
