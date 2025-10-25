import express from 'express';
import bodyParser from 'body-parser';
import Web3 from 'web3';
import fs from 'fs';
import { ecsign, toBuffer } from 'ethereumjs-util';
import { encrypt as eciesEncrypt, decrypt as eciesDecrypt } from 'eciesjs';
import { ethers } from 'ethers';
import axios from 'axios';
import pkg from 'elliptic';
const { ec: EC } = pkg;

// --- Constants to mimic app storage ---
const patientPrivateKey = '97e9f6f57855c21fcfd066907cf8d8ddd247a052ab4aaafa68d3f0ee04914590';
const patientPublicKey = '0x04875b2fca1ee80bc7b007050960b17ee0967514a82460aaf758b13439ff8ad84afc21d5460ef99917401bc13346746dbb7872e12d0da857eb2051a39fbb3f667d';
const healthId = '0xcf648fa3ef5f9f6da94b60513c5d7a791b267789';
const encryptedSymKeyForPatient = '0x048fb95dfab60870eacd066b307cf45550f8e4ff9c67e86fd8a0d24b1caccf59b4a816b112e60ef3c983b8eca9cb003159d66ee26e5a231ad55b0014c7ffac68e7df90e85c1950d9df8fd32da66830fa230350fc88e3c98061f9aaf8ea9bcfc0e9ba6cb8b28c7e0e4f8a13826cd36e11d912515f4f8c9a1fc39d54e614abf7de66';
const ipfsHash = 'QmPYaoG8P9WKg4jZ7LLtd9yEBWn8UQWoxFMWgdgsnvoReu';
const patientAddress = '0xd01381a77d68c24cf4f6a19d2c9792760824be71';

const app = express();
app.use(bodyParser.json());

const web3 = new Web3('http://localhost:8548');
const abi = JSON.parse(fs.readFileSync('build/health.abi', 'utf8'));
const contract = new web3.eth.Contract(abi, healthId);

// Helper to convert BigInt to string for JSON serialization
function serializeBigInt(obj) {
  return JSON.parse(JSON.stringify(obj, (key, value) =>
    typeof value === 'bigint' ? value.toString() : value
  ));
}

// --- Set Pseudonym ---
app.post('/set-pseudonym', async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Missing password' });
    
    // Ethers v6 syntax
    const passwordHash = ethers.keccak256(ethers.toUtf8Bytes(password));
    const saltBytes = ethers.randomBytes(32);
    const salt = ethers.hexlify(saltBytes);
    
    const provider = new ethers.JsonRpcProvider('http://localhost:8548');
    const wallet = new ethers.Wallet(patientPrivateKey, provider);
    const ethersContract = new ethers.Contract(healthId, abi, wallet);
    
    const tx = await ethersContract.setPseudonym(salt, passwordHash);
    await tx.wait();
    
    res.json(serializeBigInt({ status: 'Pseudonym set', txHash: tx.hash, salt }));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Get Authorized Hospitals ---
app.get('/authorized-hospitals', async (req, res) => {
  try {
    const message = web3.utils.padLeft(healthId.toLowerCase(), 64);
    const messageHash = web3.utils.keccak256(message);
    const { v, r, s } = ecsign(
      toBuffer(messageHash),
      toBuffer('0x' + patientPrivateKey)
    );
    const hospitals = await contract.methods.getAuthorizedHospitals(
      message,
      v,
      '0x' + r.toString('hex'),
      '0x' + s.toString('hex')
    ).call({ from: patientAddress });
    res.json({ hospitals });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Authorize Hospital ---
app.post('/authorize-hospital', async (req, res) => {
  try {
    const { newHospital, hospitalPubKeyHex } = req.body;
    if (!newHospital || !hospitalPubKeyHex) return res.status(400).json({ error: 'Missing newHospital or hospitalPubKeyHex' });
    const hospitalPubKeyBuffer = Buffer.from(hospitalPubKeyHex.replace(/^0x/, ''), 'hex');
    const patientPrivKeyBuffer = Buffer.from(patientPrivateKey, 'hex');
    const encryptedSymKeyBuffer = Buffer.from(encryptedSymKeyForPatient.replace(/^0x/, ''), 'hex');
    const symmetricKey = eciesDecrypt(patientPrivKeyBuffer, encryptedSymKeyBuffer);
    const encryptedSymKeyForHospital = eciesEncrypt(hospitalPubKeyBuffer, symmetricKey);
    const message = web3.utils.padLeft(newHospital.toLowerCase(), 64);
    const messageHash = web3.utils.keccak256(message);
    const { v, r, s } = ecsign(
      toBuffer(messageHash),
      toBuffer('0x' + patientPrivateKey)
    );
    const txData = contract.methods.authorizeHospital(
      newHospital,
      '0x' + encryptedSymKeyForHospital.toString('hex'),
      message,
      v,
      '0x' + r.toString('hex'),
      '0x' + s.toString('hex')
    ).encodeABI();
    const nonce = await web3.eth.getTransactionCount(patientAddress, 'pending');
    const gas = await contract.methods.authorizeHospital(
      newHospital,
      '0x' + encryptedSymKeyForHospital.toString('hex'),
      message,
      v,
      '0x' + r.toString('hex'),
      '0x' + s.toString('hex')
    ).estimateGas({ from: patientAddress });
    const gasPrice = await web3.eth.getGasPrice();
    const tx = {
      from: patientAddress,
      to: healthId,
      data: txData,
      gas,
      gasPrice,
      nonce,
    };
    const signed = await web3.eth.accounts.signTransaction(tx, '0x' + patientPrivateKey);
    const receipt = await web3.eth.sendSignedTransaction(signed.rawTransaction);
    res.json(serializeBigInt({ status: 'Hospital authorized', receipt }));
  } catch (err) {
    console.error('[ERROR] Authorization failed:', err.message);
    console.error('[ERROR] Full error:', err);
    res.status(500).json({ 
      error: err.message,
      details: err.innerError?.message || err.reason || 'Unknown error',
      stack: err.stack 
    });
  }
});

// --- Revoke Hospital ---
app.post('/revoke-hospital', async (req, res) => {
  try {
    const { hospitalToRevoke } = req.body;
    if (!hospitalToRevoke) return res.status(400).json({ error: 'Missing hospitalToRevoke' });
    const message = web3.utils.padLeft(hospitalToRevoke.toLowerCase(), 64);
    const messageHash = web3.utils.keccak256(message);
    const { v, r, s } = ecsign(
      toBuffer(messageHash),
      toBuffer('0x' + patientPrivateKey)
    );
    const txData = contract.methods.revokeHospital(
      hospitalToRevoke,
      message,
      v,
      '0x' + r.toString('hex'),
      '0x' + s.toString('hex')
    ).encodeABI();
    const nonce = await web3.eth.getTransactionCount(patientAddress, 'pending');
    const gas = await contract.methods.revokeHospital(
      hospitalToRevoke,
      message,
      v,
      '0x' + r.toString('hex'),
      '0x' + s.toString('hex')
    ).estimateGas({ from: patientAddress });
    const gasPrice = await web3.eth.getGasPrice();
    const tx = {
      from: patientAddress,
      to: healthId,
      data: txData,
      gas,
      gasPrice,
      nonce,
    };
    const signed = await web3.eth.accounts.signTransaction(tx, '0x' + patientPrivateKey);
    const receipt = await web3.eth.sendSignedTransaction(signed.rawTransaction);
    res.json(serializeBigInt({ status: 'Hospital revoked', receipt }));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Sync Authorized Hospitals with New Symmetric Key ---
app.post('/sync-authorized-hospitals', async (req, res) => {
  try {
    const { 
      encryptedSymKeyFromHospital, 
      hospitalAddress: requestingHospitalAddress 
    } = req.body;
    
    if (!encryptedSymKeyFromHospital || !requestingHospitalAddress) {
      return res.status(400).json({ 
        error: 'Missing encryptedSymKeyFromHospital or hospitalAddress' 
      });
    }

    console.log('[INFO] Sync authorized hospitals request received');
    console.log('[INFO] Requesting hospital:', requestingHospitalAddress);

    // Step 1: Decrypt the symmetric key using patient's private key
    const patientPrivKeyBuffer = Buffer.from(patientPrivateKey, 'hex');
    const encryptedSymKeyBuffer = Buffer.from(
      encryptedSymKeyFromHospital.replace(/^0x/, ''), 
      'hex'
    );
    const symmetricKey = eciesDecrypt(patientPrivKeyBuffer, encryptedSymKeyBuffer);
    
    console.log('[INFO] Symmetric key decrypted successfully');
    console.log('[DEBUG] Symmetric key length:', symmetricKey.length, 'bytes');

    // Step 2: Get list of authorized hospitals from the contract
    const message = web3.utils.padLeft(healthId.toLowerCase(), 64);
    const messageHash = web3.utils.keccak256(message);
    const { v, r, s } = ecsign(
      toBuffer(messageHash),
      toBuffer('0x' + patientPrivateKey)
    );
    
    const authorizedHospitals = await contract.methods.getAuthorizedHospitals(
      message,
      v,
      '0x' + r.toString('hex'),
      '0x' + s.toString('hex')
    ).call({ from: patientAddress });

    console.log('[INFO] Retrieved authorized hospitals:', authorizedHospitals.length);

    // Step 3: Get registry contract to fetch hospital public keys
    const registryAddress = '0x9923fFb3d17Afa87B2Ec53833648f503a4ef7980';
    const registryAbi = JSON.parse(fs.readFileSync('build/registry.abi', 'utf8'));
    const registryContract = new web3.eth.Contract(registryAbi, registryAddress);

    // Step 4: For each authorized hospital, encrypt the symmetric key with their public key
    const hospitals = [];
    const encryptedKeys = [];

    for (const hospitalAddr of authorizedHospitals) {
      try {
        // Get hospital public key from registry
        const hospitalPubKeyHex = await registryContract.methods.getHospitalPublicKey(
          hospitalAddr
        ).call();
        
        console.log(`[INFO] Encrypting key for hospital: ${hospitalAddr}`);
        console.log(`[DEBUG] Hospital public key (first 20 chars): ${hospitalPubKeyHex.substring(0, 20)}...`);
        
        // Encrypt symmetric key with hospital's public key
        const hospitalPubKeyBuffer = Buffer.from(
          hospitalPubKeyHex.replace(/^0x/, ''), 
          'hex'
        );
        const encryptedKeyForHospital = eciesEncrypt(hospitalPubKeyBuffer, symmetricKey);
        
        hospitals.push(hospitalAddr);
        encryptedKeys.push('0x' + encryptedKeyForHospital.toString('hex'));
        
        console.log(`[INFO] Key encrypted for hospital: ${hospitalAddr}`);
      } catch (error) {
        console.error(`[ERROR] Failed to process hospital ${hospitalAddr}:`, error.message);
        // Continue with other hospitals even if one fails
      }
    }

    console.log('[INFO] Encrypted keys prepared for', hospitals.length, 'hospitals');

    // Step 5: Call syncAuthorizedHospitals on the contract
    const txData = contract.methods.syncAuthorizedHospitals(
      hospitals,
      encryptedKeys
    ).encodeABI();

    const nonce = await web3.eth.getTransactionCount(patientAddress, 'pending');
    const gas = await contract.methods.syncAuthorizedHospitals(
      hospitals,
      encryptedKeys
    ).estimateGas({ from: patientAddress });
    const gasPrice = await web3.eth.getGasPrice();

    const tx = {
      from: patientAddress,
      to: healthId,
      data: txData,
      gas,
      gasPrice,
      nonce,
    };

    console.log('[INFO] Signing and sending transaction...');
    const signed = await web3.eth.accounts.signTransaction(tx, '0x' + patientPrivateKey);
    const receipt = await web3.eth.sendSignedTransaction(signed.rawTransaction);

    console.log('[INFO] Sync completed successfully');
    console.log('[INFO] Transaction hash:', receipt.transactionHash);

    res.json(serializeBigInt({ 
      status: 'Authorized hospitals synced successfully',
      hospitalsSynced: hospitals.length,
      hospitals: hospitals,
      transactionHash: receipt.transactionHash,
      receipt 
    }));

  } catch (err) {
    console.error('[ERROR] Sync failed:', err.message);
    console.error('[ERROR] Stack:', err.stack);
    res.status(500).json({ 
      error: err.message,
      stack: err.stack 
    });
  }
});

app.listen(3001, () => {
  console.log('Patient API running on port 3001');
}); 