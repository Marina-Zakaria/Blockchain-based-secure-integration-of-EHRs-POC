import express from 'express';
import bodyParser from 'body-parser';
import { create as createIpfsClient } from 'ipfs-http-client';
import crypto from 'crypto';
import { encrypt as eciesEncrypt, decrypt as eciesDecrypt } from 'eciesjs';
import { JsonRpcProvider, Wallet, ContractFactory } from 'ethers';
import fs from 'fs';
import Web3 from 'web3';
import pkg from 'elliptic';
const { ec: EC } = pkg;

// --- PII Class Definition ---
class PII {
  constructor({ name, nationalId, phone, gender, maritalStatus, nationality, address }) {
    this.name = name;
    this.nationalId = nationalId;
    this.phone = phone;
    this.gender = gender;
    this.maritalStatus = maritalStatus;
    this.nationality = nationality;
    this.address = address;
  }
}

const app = express();
app.use(bodyParser.json());

const ipfs = createIpfsClient({ url: 'http://localhost:5001' });
const abi = JSON.parse(fs.readFileSync('build/health.abi', 'utf8'));
const bytecode = fs.readFileSync('build/health.bin', 'utf8').toString().trim();
const hospitalPrivateKey = 'c6162cb5ba0776b17db3bed6abdc5b6918d691d0454c9e5a96396484d1d90666'; // Replace with your key
const provider = new JsonRpcProvider('http://localhost:8548');
const wallet = new Wallet(hospitalPrivateKey, provider);
const registryAddress = '0x3eDADD129Feb03a23D978B45F87964aFe8BEB054'; // Replace with your registry address
const web3 = new Web3('http://localhost:8548'); // Hospital node RPC
const from = wallet.address;
const password = fs.readFileSync('password.txt', 'utf8').trim();

// Helper to get the hospital's own public key (uncompressed)
const ec = new EC('secp256k1');
function getUncompressedPublicKey(privateKeyHex) {
  const key = ec.keyFromPrivate(privateKeyHex, 'hex');
  return Buffer.from(key.getPublic(false, 'hex'), 'hex'); // uncompressed, 65 bytes
}

function deriveSymmetricKey(patientAddress) {
  // Derive a unique symmetric key per patient: keccak256(patientAddress + random salt)
  const salt = crypto.randomBytes(32);
  const keyMaterial = Buffer.concat([
    Buffer.from(patientAddress.replace(/^0x/, ''), 'hex'),
    salt
  ]);
  const hash = crypto.createHash('sha3-256').update(keyMaterial).digest();
  return { symmetricKey: hash, salt: salt.toString('hex') };
}

function encryptPII(pii, symmetricKey) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);
  let encrypted = cipher.update(JSON.stringify(pii), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag();
  return {
    encryptedData: encrypted,
    iv: iv.toString('hex'),
    tag: tag.toString('hex')
  };
}

app.post('/register-patient', async (req, res) => {
  const startTotal = Date.now();
  try {
    const { pii, patientPublicKey, patientAddress } = req.body;
    if (!pii || !patientPublicKey || !patientAddress) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    console.log('[INFO] Received registration request for patient:', patientAddress);
    const startPII = Date.now();
    // 1. Create PII object
    const piiObj = new PII(pii);
    console.log(`[INFO] PII object created in ${Date.now() - startPII} ms.`);

    // 2. Derive unique symmetric key for this patient
    const startKey = Date.now();
    const { symmetricKey, salt } = deriveSymmetricKey(patientAddress);
    console.log(`[INFO] Symmetric key derived in ${Date.now() - startKey} ms.`);

    // 3. Encrypt PII
    const startEncrypt = Date.now();
    const encryptedPII = encryptPII(piiObj, symmetricKey);
    encryptedPII.salt = salt; // Include salt for patient to reconstruct key
    console.log(`[INFO] PII encrypted in ${Date.now() - startEncrypt} ms.`);

    // 4. Upload encrypted PII to IPFS
    const startIpfs = Date.now();
    console.log('[DEBUG] encryptedPIIObj:', encryptedPII);
    const { cid } = await ipfs.add(JSON.stringify(encryptedPII));
    const ipfsHash = cid.toString();
    console.log(`[INFO] Encrypted PII uploaded to IPFS in ${Date.now() - startIpfs} ms. IPFS hash: ${ipfsHash}`);

    // Encrypt symmetric key with hospital's own public key
    const hospitalPubKeyBuffer = getUncompressedPublicKey(hospitalPrivateKey);
    const encryptedSymKeyForHospital = eciesEncrypt(hospitalPubKeyBuffer, symmetricKey);

    // 5. Deploy HealthSC contract (using web3.js for compatibility)
    const startDeploy = Date.now();
    await web3.eth.personal.unlockAccount(from, password, 600);
    const contract = new web3.eth.Contract(abi);
    const deployTx = contract.deploy({
      data: bytecode.startsWith('0x') ? bytecode : '0x' + bytecode,
      arguments: [
        registryAddress,
        patientAddress,
        patientPublicKey,
        ipfsHash,
        from,
        '0x' + encryptedSymKeyForHospital.toString('hex')
      ]
    });
    const instance = await deployTx.send({ from, gas: 6000000, gasPrice: '0' });
    console.log(`[INFO] HealthSC contract deployed in ${Date.now() - startDeploy} ms. Address: ${instance.options.address}`);

    // 6. Encrypt symmetric key with patient's public key (ECIES)
    const startEcies = Date.now();
    const encryptedSymKey = eciesEncrypt(
      Buffer.from(patientPublicKey.replace(/^0x/, ''), 'hex'),
      symmetricKey
    ).toString('hex');
    console.log(`[INFO] Symmetric key encrypted for patient in ${Date.now() - startEcies} ms.`);

    // 7. Respond with healthID, ipfsHash, encrypted symmetric key, and salt
    const totalTime = Date.now() - startTotal;
    console.log(`[INFO] Registration process completed in ${totalTime} ms.`);
    res.json({
      healthID: instance.options.address,
      ipfsHash,
      encryptedSymKey
    });
  } catch (err) {
    console.error('[ERROR]', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/get-pii', async (req, res) => {
  const startTotal = Date.now();
  try {
    const { healthID } = req.body;
    if (!healthID) {
      return res.status(400).json({ error: 'Missing healthID' });
    }

    console.log(`[INFO] Received PII retrieval request for healthID: ${healthID}`);
    const startContract = Date.now();
    // 1. Get contract instance
    const contract = new web3.eth.Contract(abi, healthID);
    console.log(`[INFO] Contract instance created in ${Date.now() - startContract} ms.`);

    // 2. Call getPIIReference to get ipfsHash and encrypted symmetric key
    const startChain = Date.now();
    const piiRef = await contract.methods.getPIIReference().call({ from });
    const ipfsHash = piiRef[0];
    const encryptedSymKeyHex = piiRef[1];
    const encryptedSymKey = Buffer.from(encryptedSymKeyHex.replace(/^0x/, ''), 'hex');
    console.log(`[INFO] Fetched ipfsHash and encrypted symmetric key from chain in ${Date.now() - startChain} ms. IPFS hash: ${ipfsHash}`);

    // 3. Decrypt the symmetric key using the hardcoded hospital's private key
    const startDecryptKey = Date.now();
    const ec = new EC('secp256k1');
    const key = ec.keyFromPrivate(hospitalPrivateKey, 'hex');
    const hospitalPrivKeyBuffer = Buffer.from(hospitalPrivateKey, 'hex');
    const decryptedSymKey = eciesDecrypt(hospitalPrivKeyBuffer, encryptedSymKey);
    console.log('[DEBUG] Decrypted symmetric key:', decryptedSymKey.toString('hex'));
    console.log(`[INFO] Symmetric key decrypted in ${Date.now() - startDecryptKey} ms.`);

    if (decryptedSymKey.length !== 32) {
      throw new Error('Decrypted symmetric key is not 32 bytes');
    }

    // 4. Fetch encrypted PII from IPFS
    const startIpfs = Date.now();
    let encryptedPIIBuffer = Buffer.alloc(0);
    for await (const chunk of ipfs.cat(ipfsHash)) {
      encryptedPIIBuffer = Buffer.concat([encryptedPIIBuffer, chunk]);
    }
    const encryptedPIIObj = JSON.parse(encryptedPIIBuffer.toString());
    console.log('[DEBUG] Encrypted PII object:', encryptedPIIObj);
    console.log(`[INFO] Encrypted PII fetched from IPFS in ${Date.now() - startIpfs} ms.`);

    // 5. Decrypt the PII
    const startDecryptPII = Date.now();
    const iv = Buffer.from(encryptedPIIObj.iv, 'hex');
    const tag = Buffer.from(encryptedPIIObj.tag, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', decryptedSymKey, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(encryptedPIIObj.encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    console.log('[DEBUG] Decrypted PII string:', decrypted);
    const pii = JSON.parse(decrypted);
    console.log(`[INFO] PII decrypted in ${Date.now() - startDecryptPII} ms.`);

    const totalTime = Date.now() - startTotal;
    console.log(`[INFO] PII retrieval process completed in ${totalTime} ms.`);
    res.json({ pii });
  } catch (err) {
    console.error('[ERROR]', err);
    res.status(500).json({ error: err.message });
  }
});

// TODO: POST /get-token
// This endpoint should accept a JSON body with { healthID }
// 1. It should generate or retrieve the hospital's address.
// 2. It should create and sign the required message for the gateway (using the hospital's private key).
// 3. It should make a POST request to the gateway API /get-pseudonym-for-hospital endpoint with:
//    - healthID
//    - hospitalAddress
//    - message (padded and hex-encoded)
//    - v, r, s (signature components)
// 4. It should receive the pseudonym from the gateway API and use it to generate or return a token for the client.
// 5. Respond with the token (and optionally the pseudonym) in the response.

app.listen(3000, () => {
  console.log('Hospital API running on port 3000');
}); 