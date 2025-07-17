# Secure Medical Data Sharing Blockchain Network

## Overview

This project implements a secure, permissioned blockchain network for medical data sharing between healthcare facilities (such as hospitals and clinics). The network leverages Quorum and Clique (Proof-of-Authority) consensus to ensure that only authorized participants can join, share, and access sensitive medical data. The system provides strong access control, auditability, and trust, with regulatory authorities acting as network gatekeepers.

## Architecture

### Node Roles
- **Sealer Nodes (Regulators/Authorities):** Register and manage hospitals, doctors, and gateways. Participate in consensus and enforce network rules.
- **Full Nodes (Hospitals/Clinics):** Registered by authorities, can deploy and interact with patient smart contracts.
- **Gateways:** Registered by regulators, act as intermediaries for privacy-preserving pseudonym retrieval.
- **Patients:** Interact via APIs or scripts, control access to their data.

### Data Sharing Model
- Only registered hospitals/clinics can join and access data.
- All actions (registration, attestation, revocation) are recorded on-chain for transparency and auditability.
- Authority nodes control which facilities are allowed to connect and participate.

## Features
- **Fine-grained access control** for patient data using smart contracts.
- **Regulator, hospital, doctor, gateway registration and management** via on-chain registry.
- **Patient-controlled authorization** for hospitals to access their data.
- **Encrypted PII storage** on IPFS, with symmetric keys managed via ECIES.
- **Auditability:** All actions emit events and are queryable on-chain.
- **APIs for all roles:** Hospital, Patient, Gateway, Regulator.
- **Signature-based authentication** for sensitive operations.

## API Summary Table

| API         | Endpoint                        | Method | Description                                      |
|-------------|----------------------------------|--------|--------------------------------------------------|
| Hospital    | /register-patient               | POST   | Register patient, deploy contract, store PII     |
| Hospital    | /get-pii                        | POST   | Retrieve and decrypt patient PII                 |
| Patient     | /set-pseudonym                  | POST   | Set patient pseudonym                            |
| Patient     | /authorized-hospitals           | GET    | List authorized hospitals for patient            |
| Patient     | /authorize-hospital             | POST   | Authorize a new hospital                         |
| Patient     | /revoke-hospital                | POST   | Revoke hospital authorization                    |
| Gateway     | /get-pseudonym-for-hospital     | POST   | Retrieve patient pseudonym for hospital          |
| Regulator   | /add-regulator                  | POST   | Add a new regulator                              |
| Regulator   | /register-hospital              | POST   | Register a hospital                              |
| Regulator   | /deregister-hospital            | POST   | Deregister a hospital                            |
| Regulator   | /register-doctor                | POST   | Register a doctor                                |
| Regulator   | /deregister-doctor              | POST   | Deregister a doctor                              |
| Regulator   | /register-gateway               | POST   | Register a gateway                               |
| Regulator   | /registry-list                  | GET    | List all registered entities                     |

## Installation & Requirements

### System Requirements
- Node.js (v14+ recommended)
- npm
- Quorum (geth)
- IPFS (go-ipfs or js-ipfs)

### Project Dependencies
- web3
- ethers
- eciesjs
- elliptic
- body-parser
- express
- ethereumjs-util

Install all Node.js dependencies:
   ```bash
npm install
```

### Setting Up the Blockchain
1. **Initialize nodes:**
   ```bash
   geth --datadir node1 init genesis.json
   # Repeat for node2 ... nodeN
   ```
2. **Start nodes:**
   ```bash
   geth --datadir node1 --networkid 1001 --mine --miner.threads 1 --syncmode full --port 30303 --http --http.addr 0.0.0.0 --http.port 8545 --unlock 0 --password password.txt --allow-insecure-unlock --nodiscover --verbosity 3 --http.api admin,db,eth,debug,miner,net,shh,txpool,personal,web3,quorum
   ```
   - For observer nodes (hospitals/clinics), omit `--mine` and use their respective ports.
3. **Start IPFS:**
   ```bash
   ipfs init
   ipfs daemon
   ```
4. **Compile contracts:**
   ```bash
   npx truffle compile
   # Ensure EVM version is set to 'istanbul' in truffle-config.js
   ```
5. **Deploy contracts:**
   ```bash
   node deploy.js
   # Or use the deployment scripts as needed
   ```

### Troubleshooting Installation
- **invalid opcode: opcode 0x5f not defined:** Recompile contracts with `evmVersion: 'istanbul'`.
- **code couldn't be stored:** Check for EVM incompatibility or out-of-gas errors.
- **Node not connecting:** Ensure enode addresses and static-nodes.json are correct.
- **IPFS not running:** Ensure `ipfs daemon` is active and listening on `localhost:5001`.
- **web3/ethers errors:** Ensure all dependencies are installed and correct versions are used.
- **Signature errors:** See troubleshooting below.

## API Endpoints & Functionality

### Hospital API (`hospital_api.mjs`)
- **POST /register-patient**
  - Registers a new patient, encrypts and uploads PII to IPFS, deploys HealthSC contract.
  - **Input:** `{ pii, patientPublicKey, patientAddress }`
  - **Output:** `{ healthID, ipfsHash, encryptedSymKey }`
- **POST /get-pii**
  - Retrieves and decrypts a patient's PII for an authorized hospital.
  - **Input:** `{ healthID }`
  - **Output:** `{ pii }`

### Patient API (`patient_api.mjs`)
- **POST /set-pseudonym**
  - Sets the patient's pseudonym (one-time, salted hash).
  - **Input:** `{ password }`
  - **Output:** `{ status, txHash, salt }`
- **GET /authorized-hospitals**
  - Lists hospitals authorized for the patient.
  - **Output:** `{ hospitals }`
- **POST /authorize-hospital**
  - Authorizes a new hospital for the patient.
  - **Input:** `{ newHospital, hospitalPubKeyHex }`
  - **Output:** `{ status, receipt }`
- **POST /revoke-hospital**
  - Revokes a hospital's authorization.
  - **Input:** `{ hospitalToRevoke }`
  - **Output:** `{ status, receipt }`

### Gateway API (`gateway_api.mjs`)
- **POST /get-pseudonym-for-hospital**
  - Retrieves a patient's pseudonym for a hospital, using a signed message.
  - **Input:** `{ healthID, hospitalAddress, message, v, r, s }`
  - **Output:** `{ pseudonym }`

### Regulator API (`regulator_api.mjs`)
- **POST /add-regulator**
  - Adds a new regulator.
  - **Input:** `{ regulatorAddress }`
  - **Output:** `{ status, receipt }`
- **POST /register-hospital**
  - Registers a hospital.
  - **Input:** `{ hospitalAddress, hospitalPublicKey }`
  - **Output:** `{ status, receipt }`
- **POST /deregister-hospital**
  - Deregisters a hospital.
  - **Input:** `{ hospitalAddress }`
  - **Output:** `{ status, receipt }`
- **POST /register-doctor**
  - Registers a doctor.
  - **Input:** `{ doctorAddress }`
  - **Output:** `{ status, receipt }`
- **POST /deregister-doctor**
  - Deregisters a doctor.
  - **Input:** `{ doctorAddress }`
  - **Output:** `{ status, receipt }`
- **POST /register-gateway**
  - Registers a gateway.
  - **Input:** `{ gatewayAddress }`
  - **Output:** `{ status, receipt }`
- **GET /registry-list**
  - Lists all registered hospitals, doctors, regulators, and gateways.
  - **Output:** `{ hospitals, doctors, regulators, gateways }`

## Security Model
- **Access Control:** Only registered regulators can add/remove hospitals, doctors, and gateways. Only registered hospitals can deploy patient contracts. Only patients can authorize/revoke hospitals for their data.
- **Auditability:** All actions are logged on-chain and can be traced via events.
- **Key Management:** Each node has its own keystore and password. Passwords and private keys are stored in plaintext for development convenience—**do not use in production**.
- **Network Integrity:** Sealer nodes enforce membership and consensus, preventing unauthorized access.

## Testing & Usage
- Use Postman, curl, or any HTTP client to interact with the APIs.
- Example request to register a patient:
  ```bash
  curl -X POST http://localhost:3000/register-patient \
    -H 'Content-Type: application/json' \
    -d '{ "pii": { "name": "Alice", ... }, "patientPublicKey": "04...", "patientAddress": "0x..." }'
  ```
- Example request to authorize a hospital:
  ```bash
  curl -X POST http://localhost:3001/authorize-hospital \
    -H 'Content-Type: application/json' \
    -d '{ "newHospital": "0x...", "hospitalPubKeyHex": "04..." }'
  ```
- Example request to get registry list:
  ```bash
  curl http://localhost:3003/registry-list
  ```

## Troubleshooting
- **Signature verification fails:** Ensure you use raw ECDSA signing (no Ethereum prefix) with `ethereumjs-util`.
- **Contract reverts:** Check that all registration and authorization conditions are met (see error messages).
- **Node/contract not found:** Ensure all nodes are running, contracts are deployed, and ABIs are present.
- **IPFS errors:** Ensure the IPFS daemon is running and accessible.
- **API errors:** Check logs for stack traces and error messages; ensure all required fields are present in requests.

## References & Further Reading
- [Quorum Documentation](https://docs.goquorum.consensys.net/)
- [web3.js Documentation](https://web3js.readthedocs.io/)
- [Truffle Documentation](https://trufflesuite.com/docs/truffle/reference/compile/)
- [IPFS Documentation](https://docs.ipfs.tech/)

---
**This project is a proof-of-concept for secure, auditable medical data sharing using blockchain technology. For production use, ensure all security best practices are followed, including secure key management and encrypted storage.**