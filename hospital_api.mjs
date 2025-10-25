import express from 'express';
import bodyParser from 'body-parser';
import axios from 'axios';
import Web3 from 'web3';
import fs from 'fs';
import crypto from 'crypto';
import { ecsign, toBuffer } from 'ethereumjs-util';
import { create as createIpfsClient } from 'ipfs-http-client';
import { encrypt as eciesEncrypt, decrypt as eciesDecrypt } from 'eciesjs';
import pkg from 'elliptic';
const { ec: EC } = pkg;

// --- Configuration from environment variables or command line arguments ---
const config = {
  port: process.env.HOSPITAL_PORT || process.argv[2] || 3000,
  rpcUrl: process.env.HOSPITAL_RPC || process.argv[3] || 'http://localhost:8548',
  privateKeyFile: process.env.HOSPITAL_KEY_FILE || process.argv[4] || 'node3_private_key.txt',
  hospitalName: process.env.HOSPITAL_NAME || process.argv[5] || 'Hospital_Node3',
  registryAddress: process.env.REGISTRY_ADDRESS || '0x9923fFb3d17Afa87B2Ec53833648f503a4ef7980',
  ipfsUrl: process.env.IPFS_URL || 'http://localhost:5001'
};

const app = express();

// Increased limit for large EHR uploads
app.use(bodyParser.json({ limit: '50mb' }));

// Load hospital credentials
const hospitalPrivateKey = fs.readFileSync(config.privateKeyFile, 'utf8').trim();
const web3 = new Web3(new Web3.providers.HttpProvider(config.rpcUrl));
const hospitalAccount = web3.eth.accounts.privateKeyToAccount('0x' + hospitalPrivateKey);
const hospitalAddress = hospitalAccount.address;

const registryAddress = config.registryAddress;

// IPFS client initialization
const ipfs = createIpfsClient({ url: config.ipfsUrl });

// Load contract ABI and bytecode
const abi = JSON.parse(fs.readFileSync('build/health.abi', 'utf8'));
const bytecode = fs.readFileSync('build/health.bin', 'utf8').toString().trim();

// Helper: Get uncompressed public key from private key
const ec = new EC('secp256k1');
function getUncompressedPublicKey(privateKeyHex) {
  const key = ec.keyFromPrivate(privateKeyHex, 'hex');
  return Buffer.from(key.getPublic(false, 'hex'), 'hex'); // uncompressed, 65 bytes
}

// Helper: Generate random symmetric key
function generateSymmetricKey() {
  return crypto.randomBytes(32); // 256-bit key for AES-256
}

// Helper: Derive symmetric key from patient address (for initial registration)
function deriveSymmetricKey(patientAddress) {
  const salt = crypto.randomBytes(32);
  const keyMaterial = Buffer.concat([
    Buffer.from(patientAddress.replace(/^0x/, ''), 'hex'),
    salt
  ]);
  const hash = crypto.createHash('sha256').update(keyMaterial).digest();
  return { symmetricKey: hash, salt: salt.toString('hex') };
}

// Helper: Encrypt PII with symmetric key
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

// Helper: Decrypt PII with symmetric key
function decryptPII(encryptedPII, symmetricKey) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', symmetricKey, Buffer.from(encryptedPII.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(encryptedPII.tag, 'hex'));
  let decrypted = decipher.update(encryptedPII.encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}

// Logging utility
function log(level, message, context = {}) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    level,
    service: `HOSPITAL_API_${config.hospitalName}`,
    port: config.port,
    hospitalAddress,
    message,
    ...context
  };
  console.log(JSON.stringify(logEntry, null, 2));
}

console.log(`\n${'='.repeat(60)}`);
console.log(`✅ ${config.hospitalName} API Starting...`);
console.log(`${'='.repeat(60)}`);
console.log(`Port:              ${config.port}`);
console.log(`RPC URL:           ${config.rpcUrl}`);
console.log(`Hospital Address:  ${hospitalAddress}`);
console.log(`Private Key File:  ${config.privateKeyFile}`);
console.log(`Registry Contract: ${registryAddress}`);
console.log(`IPFS URL:          ${config.ipfsUrl}`);
console.log(`${'='.repeat(60)}\n`);

// POST /register-patient - Register new patient and deploy HealthSC contract
app.post('/register-patient', async (req, res) => {
  const requestId = crypto.randomBytes(16).toString('hex');
  const startTotal = Date.now();
  
  try {
    const { pii, patientPublicKey, patientAddress } = req.body;
    
    log('INFO', 'Patient registration request received', {
      requestId,
      patientAddress,
      hasPII: !!pii,
      hasPublicKey: !!patientPublicKey
    });

    if (!pii || !patientPublicKey || !patientAddress) {
      log('ERROR', 'Missing required fields', { requestId });
      return res.status(400).json({ 
        error: 'Missing required fields: pii, patientPublicKey, patientAddress',
        requestId 
      });
    }

    // Step 1: Derive unique symmetric key for this patient
    log('INFO', 'Deriving symmetric key', { requestId });
    const { symmetricKey, salt } = deriveSymmetricKey(patientAddress);

    // Step 2: Encrypt PII
    log('INFO', 'Encrypting PII', { requestId });
    const encryptedPII = encryptPII(pii, symmetricKey);
    encryptedPII.salt = salt;

    // Step 3: Upload encrypted PII to IPFS
    log('INFO', 'Uploading encrypted PII to IPFS', { requestId });
    const { cid } = await ipfs.add(JSON.stringify(encryptedPII));
    const ipfsHash = cid.toString();
    log('INFO', 'Encrypted PII uploaded to IPFS', { requestId, ipfsHash });

    // Step 4: Encrypt symmetric key with hospital's own public key
    log('INFO', 'Encrypting symmetric key for hospital', { requestId });
    const hospitalPubKeyBuffer = getUncompressedPublicKey(hospitalPrivateKey);
    const encryptedSymKeyForHospital = eciesEncrypt(hospitalPubKeyBuffer, symmetricKey);

    // Step 5: Deploy HealthSC contract
    log('INFO', 'Deploying HealthSC contract', { requestId });
    const contract = new web3.eth.Contract(abi);
    const deployTx = contract.deploy({
      data: bytecode.startsWith('0x') ? bytecode : '0x' + bytecode,
      arguments: [
        registryAddress,
        patientAddress,
        patientPublicKey,
        ipfsHash,
        hospitalAddress,
        '0x' + encryptedSymKeyForHospital.toString('hex')
      ]
    });

    const gas = await deployTx.estimateGas({ from: hospitalAddress });
    const gasPrice = await web3.eth.getGasPrice();
    const nonce = await web3.eth.getTransactionCount(hospitalAddress, 'pending');

    const deployData = deployTx.encodeABI();
    const tx = {
      from: hospitalAddress,
      data: deployData,
      gas,
      gasPrice,
      nonce
    };

    const signedTx = await web3.eth.accounts.signTransaction(tx, '0x' + hospitalPrivateKey);
    const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);
    const healthID = receipt.contractAddress;

    log('INFO', 'HealthSC contract deployed', { 
      requestId, 
      healthID,
      txHash: receipt.transactionHash
    });

    // Step 6: Encrypt symmetric key with patient's public key
    log('INFO', 'Encrypting symmetric key for patient', { requestId });
    const encryptedSymKey = eciesEncrypt(
      Buffer.from(patientPublicKey.replace(/^0x/, ''), 'hex'),
      symmetricKey
    ).toString('hex');

    const totalTime = Date.now() - startTotal;
    log('INFO', 'Patient registration completed', { 
      requestId, 
      healthID,
      totalTime: totalTime + 'ms'
    });

    res.json({
      status: 'success',
      healthID,
      ipfsHash,
      encryptedSymKey: '0x' + encryptedSymKey,
      salt,
      transactionHash: receipt.transactionHash,
      requestId,
      processingTime: totalTime + 'ms'
    });

  } catch (error) {
    log('ERROR', 'Patient registration failed', {
      requestId,
      error: error.message,
      stack: error.stack
    });

    res.status(500).json({ 
      error: 'Patient registration failed',
      details: error.message,
      requestId
    });
  }
});

// POST /get-pii - Retrieve and decrypt patient PII
app.post('/get-pii', async (req, res) => {
  const requestId = crypto.randomBytes(16).toString('hex');
  
  try {
    const { healthID } = req.body;
    
    log('INFO', 'PII retrieval request received', { requestId, healthID });
    
    if (!healthID) {
      log('ERROR', 'Missing healthID', { requestId });
      return res.status(400).json({ error: 'Missing healthID', requestId });
    }

    // Step 1: Get contract instance
    const contract = new web3.eth.Contract(abi, healthID);
    
    // Step 2: Call getPIIReference to get ipfsHash and encrypted symmetric key
    log('INFO', 'Fetching PII reference from blockchain', { requestId });
    const piiRef = await contract.methods.getPIIReference().call({ from: hospitalAddress });
    const ipfsHash = piiRef[0];
    const encryptedSymKeyHex = piiRef[1];
    const encryptedSymKey = Buffer.from(encryptedSymKeyHex.replace(/^0x/, ''), 'hex');
    
    log('INFO', 'PII reference retrieved', { requestId, ipfsHash });

    // Step 3: Decrypt the symmetric key using the hospital's private key
    log('INFO', 'Decrypting symmetric key', { requestId });
    const hospitalPrivKeyBuffer = Buffer.from(hospitalPrivateKey, 'hex');
    const decryptedSymKey = eciesDecrypt(hospitalPrivKeyBuffer, encryptedSymKey);
    
    if (decryptedSymKey.length !== 32) {
      throw new Error('Decrypted symmetric key is not 32 bytes');
    }

    // Step 4: Fetch encrypted PII from IPFS
    log('INFO', 'Fetching encrypted PII from IPFS', { requestId, ipfsHash });
    let encryptedPIIBuffer = Buffer.alloc(0);
    for await (const chunk of ipfs.cat(ipfsHash)) {
      encryptedPIIBuffer = Buffer.concat([encryptedPIIBuffer, chunk]);
    }
    const encryptedPIIObj = JSON.parse(encryptedPIIBuffer.toString());
    
    // Step 5: Decrypt PII using the symmetric key
    log('INFO', 'Decrypting PII', { requestId });
    const pii = decryptPII(encryptedPIIObj, decryptedSymKey);
    
    log('INFO', 'PII retrieval completed successfully', { requestId });
    
    res.json({
      status: 'success',
      pii,
      ipfsHash,
      requestId
    });
    
  } catch (error) {
    log('ERROR', 'PII retrieval failed', {
      requestId,
      error: error.message,
      stack: error.stack
    });
    
    res.status(500).json({ 
      error: 'PII retrieval failed',
      details: error.message,
      requestId
    });
  }
});

// Get token from gateway (implements proper cryptographic flow)
async function getTokenFromGateway(healthID, requestId) {
  try {
    log('INFO', 'Requesting token from gateway', {
      requestId,
      healthID,
      hospitalAddress
    });

    // Step 1: Create timestamp and nonce for replay protection
    const timestamp = Math.floor(Date.now() / 1000); // Unix timestamp in seconds
    const nonce = crypto.randomBytes(32).toString('hex');
    
    // Step 2: Construct message for signature
    // Must match what the smart contract expects
    const message = web3.utils.padLeft(healthID.toLowerCase(), 64); // 32 bytes hex string
    
    log('INFO', 'Message constructed', {
      requestId,
      timestamp,
      nonce: nonce.substring(0, 16) + '...',
      message: message.substring(0, 20) + '...'
    });
    
    // Step 3: Sign the message hash
    // Contract will do: ecrecover(keccak256(message), v, r, s)
    // So we sign keccak256(message)
    const messageHash = web3.utils.keccak256(message);
    const msgHashBuffer = toBuffer(messageHash);
    const privKeyBuffer = toBuffer('0x' + hospitalPrivateKey);
    const { v, r, s } = ecsign(msgHashBuffer, privKeyBuffer);
    
    const signature = {
      v: v,
      r: '0x' + r.toString('hex'),
      s: '0x' + s.toString('hex')
    };
    
    log('INFO', 'Message signed', {
      requestId,
      messageHash: messageHash.substring(0, 10) + '...',
      signatureV: v
    });

    // Step 5: Send request to Gateway
    // Gateway will:
    // - Verify signature
    // - Fetch encrypted pseudonym from blockchain
    // - Create token with encrypted payload and gateway signature
    const gatewayResponse = await axios.post('http://localhost:3002/get-pseudonym-for-hospital', {
      healthID,
      hospitalAddress,
      timestamp,
      nonce,
      message,
      messageHash,
      signature
    });

    log('INFO', 'Token received from gateway', {
      requestId,
      hasToken: !!gatewayResponse.data.token,
      tokenSize: JSON.stringify(gatewayResponse.data.token).length + ' bytes'
    });

    // Token structure: { encryptedPayload, gatewaySignature, gatewayAddress }
    return gatewayResponse.data.token;

  } catch (error) {
    log('ERROR', 'Token request failed', {
      requestId,
      error: error.message,
      response: error.response?.data
    });
    throw error;
  }
}

// POST /get-token - Get token for a patient
app.post('/get-token', async (req, res) => {
  const requestId = crypto.randomBytes(16).toString('hex');
  
  try {
    const { healthID } = req.body;
    
    log('INFO', 'Token request received', { requestId, healthID });
    
    if (!healthID) {
      log('ERROR', 'Missing healthID', { requestId });
      return res.status(400).json({ error: 'Missing healthID', requestId });
    }

    const token = await getTokenFromGateway(healthID, requestId);
    
    log('INFO', 'Token request completed', { requestId });

    res.json({ token, requestId });

  } catch (error) {
    log('ERROR', 'Token request failed', {
      requestId,
      error: error.message
    });

    res.status(500).json({
      error: 'Token request failed',
      details: error.message,
      requestId
    });
  }
});

// POST /upload-patient-ehr - Complete EHR upload flow
app.post('/upload-patient-ehr', async (req, res) => {
  const requestId = crypto.randomBytes(16).toString('hex');
  
  try {
    const { healthID, token, patientData, observations } = req.body;
    
    log('INFO', 'EHR upload request received', { 
      requestId,
      healthID,
      hasToken: !!token,
      hasPatientData: !!patientData,
      observationCount: observations?.length || 0
    });

    if (!healthID) {
      log('ERROR', 'Missing healthID', { requestId });
      return res.status(400).json({ error: 'Missing healthID', requestId });
    }

    // If token not provided, get it from gateway
    let uploadToken = token;
    if (!uploadToken) {
      log('INFO', 'No token provided, requesting from gateway', { requestId });
      uploadToken = await getTokenFromGateway(healthID, requestId);
    }

    log('INFO', 'Uploading EHR data to i2b2', { 
      requestId,
      tokenReceived: true
    });
    
    // Upload EHR data to i2b2/DW using the token
    // DW will:
    // - Verify gateway signature
    // - Check token expiry and nonce
    // - Decrypt encryptedPayload to get pseudonym
    // - Use pseudonym to store/retrieve patient data
    const i2b2Url = 'http://localhost:3004/upload-ehr';
    const i2b2Response = await axios.post(i2b2Url, {
      token: uploadToken,
      patientData,
      observations
    });
    
    log('INFO', 'EHR upload completed successfully', { 
      requestId,
      recordsUploaded: i2b2Response.data.recordsUploaded
    });
    
    res.json({
      status: 'success',
      message: 'EHR data uploaded successfully',
      recordsUploaded: i2b2Response.data.recordsUploaded,
      requestId
    });
    
  } catch (error) {
    log('ERROR', 'EHR upload failed', { 
      requestId,
      error: error.message,
      response: error.response?.data
    });
    
      res.status(500).json({ 
        error: 'EHR upload failed',
      details: error.response?.data?.error || error.message,
      step: error.response ? 'i2b2_upload' : 'token_generation',
        requestId
      });
  }
});

// GET /download-patient-ehr - Complete EHR download flow
app.get('/download-patient-ehr', async (req, res) => {
  const requestId = crypto.randomBytes(16).toString('hex');
  
  try {
    const { healthID } = req.query;
    
    log('INFO', 'EHR download request received', {
      requestId,
      healthID
    });

    if (!healthID) {
      log('ERROR', 'Missing healthID', { requestId });
      return res.status(400).json({ error: 'Missing healthID parameter', requestId });
    }

    log('INFO', 'Requesting token from gateway', { requestId });
    
    // Get token from gateway
    const token = await getTokenFromGateway(healthID, requestId);
    
    log('INFO', 'Downloading EHR data from i2b2', { requestId });
    
    // Download EHR data from i2b2 using the token
    const i2b2Url = `http://localhost:3004/download-ehr`;
    const i2b2Response = await axios.post(i2b2Url, { token });
    
    log('INFO', 'EHR download completed successfully', { 
      requestId,
      recordCount: i2b2Response.data.recordCount
    });
    
    res.json({
      status: 'success',
      patientData: i2b2Response.data.patientData,
      observations: i2b2Response.data.observations,
      recordCount: i2b2Response.data.recordCount,
      requestId
    });
    
  } catch (error) {
    log('ERROR', 'EHR download failed', { 
      requestId,
      error: error.message,
      response: error.response?.data
    });
    
      res.status(500).json({ 
        error: 'EHR download failed',
      details: error.response?.data?.error || error.message,
        requestId
      });
  }
});

// POST /update-patient-pii - Update patient PII with new encrypted data
app.post('/update-patient-pii', async (req, res) => {
  const requestId = crypto.randomBytes(16).toString('hex');
  
  try {
    const { healthID, newPII, patientPublicKey, patientApiUrl } = req.body;
    
    log('INFO', 'PII update request received', { 
      requestId,
      healthID,
      hasNewPII: !!newPII,
      hasPatientPublicKey: !!patientPublicKey,
      patientApiUrl: patientApiUrl || 'http://localhost:3001'
    });

    // Validate required fields
    if (!healthID) {
      log('ERROR', 'Missing healthID', { requestId });
      return res.status(400).json({ error: 'Missing healthID', requestId });
    }
    
    if (!newPII) {
      log('ERROR', 'Missing newPII', { requestId });
      return res.status(400).json({ error: 'Missing newPII data', requestId });
    }

    if (!patientPublicKey) {
      log('ERROR', 'Missing patientPublicKey', { requestId });
      return res.status(400).json({ error: 'Missing patientPublicKey', requestId });
    }

    // Step 1: Generate new symmetric key
    log('INFO', 'Generating new symmetric key', { requestId });
    const newSymmetricKey = generateSymmetricKey();
    
    // Step 2: Encrypt PII with new symmetric key
    log('INFO', 'Encrypting PII with new symmetric key', { requestId });
    const encryptedPII = encryptPII(newPII, newSymmetricKey);
    
    // Step 3: Upload encrypted PII to IPFS
    log('INFO', 'Uploading encrypted PII to IPFS', { requestId });
    const { cid } = await ipfs.add(JSON.stringify(encryptedPII));
    const newIpfsHash = cid.toString();
    log('INFO', 'Encrypted PII uploaded to IPFS', { 
      requestId,
      newIpfsHash 
    });

    // Step 4: Load Health contract
    const abi = JSON.parse(fs.readFileSync('build/health.abi', 'utf8'));
    const contract = new web3.eth.Contract(abi, healthID);

    // Step 5: Update IPFS hash on blockchain
    log('INFO', 'Updating IPFS hash on blockchain', { requestId });
    const updateTxData = contract.methods.updatePIIHash(newIpfsHash).encodeABI();
    
    const nonce = await web3.eth.getTransactionCount(hospitalAddress, 'pending');
    const gasEstimate = await contract.methods.updatePIIHash(newIpfsHash).estimateGas({ 
      from: hospitalAddress 
    });
    const gasPrice = await web3.eth.getGasPrice();

    const updateTx = {
      from: hospitalAddress,
      to: healthID,
      data: updateTxData,
      gas: gasEstimate,
      gasPrice,
      nonce
    };

    const signedUpdateTx = await web3.eth.accounts.signTransaction(
      updateTx, 
      '0x' + hospitalPrivateKey
    );
    const updateReceipt = await web3.eth.sendSignedTransaction(
      signedUpdateTx.rawTransaction
    );

    log('INFO', 'IPFS hash updated on blockchain', { 
      requestId,
      txHash: updateReceipt.transactionHash
    });

    // Step 6: Encrypt symmetric key with patient's public key
    log('INFO', 'Encrypting symmetric key for patient', { requestId });
    const patientPubKeyBuffer = Buffer.from(
      patientPublicKey.replace(/^0x/, ''), 
      'hex'
    );
    const encryptedSymKeyForPatient = eciesEncrypt(
      patientPubKeyBuffer, 
      newSymmetricKey
    );
    const encryptedSymKeyForPatientHex = '0x' + encryptedSymKeyForPatient.toString('hex');

    // Step 7: Call patient API to sync all authorized hospitals
    const patientApiEndpoint = patientApiUrl || 'http://localhost:3001';
    log('INFO', 'Calling patient API to sync authorized hospitals', { 
      requestId,
      patientApiEndpoint 
    });
    
    try {
      const syncResponse = await axios.post(`${patientApiEndpoint}/sync-authorized-hospitals`, {
        encryptedSymKeyFromHospital: encryptedSymKeyForPatientHex,
        hospitalAddress: hospitalAddress
      });
      
      log('INFO', 'Patient sync completed successfully', {
        requestId,
        hospitalsSynced: syncResponse.data.hospitalsSynced,
        syncTxHash: syncResponse.data.transactionHash
      });

      res.json({
        status: 'success',
        message: 'Patient PII updated and all authorized hospitals synced successfully',
        newIpfsHash,
        updateTxHash: updateReceipt.transactionHash,
        syncResult: {
          hospitalsSynced: syncResponse.data.hospitalsSynced,
          hospitals: syncResponse.data.hospitals,
          syncTxHash: syncResponse.data.transactionHash
        },
        requestId
      });

    } catch (syncError) {
      log('ERROR', 'Patient sync failed', {
        requestId,
        error: syncError.message,
        response: syncError.response?.data
      });
      
      // PII was updated but sync failed - return partial success
      res.status(207).json({
        status: 'partial_success',
        message: 'Patient PII updated successfully, but hospital sync failed',
        newIpfsHash,
        updateTxHash: updateReceipt.transactionHash,
        encryptedSymKeyForPatient: encryptedSymKeyForPatientHex,
        hospitalAddress,
        syncError: syncError.response?.data || syncError.message,
        requestId,
        note: 'Patient needs to manually call /sync-authorized-hospitals'
      });
    }

  } catch (error) {
    log('ERROR', 'PII update failed', { 
      requestId,
      error: error.message,
      stack: error.stack
    });
    
    res.status(500).json({ 
      error: 'PII update failed',
      details: error.message,
      requestId
    });
  }
});

app.listen(config.port, () => {
  log('INFO', `${config.hospitalName} API started`, {
    port: config.port,
    hospitalAddress,
    registryAddress,
    rpcUrl: config.rpcUrl
  });
  console.log(`\n✅ ${config.hospitalName} API listening on port ${config.port}`);
  console.log(`✅ Ready to accept requests\n`);
});
