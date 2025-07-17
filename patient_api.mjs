import express from 'express';
import bodyParser from 'body-parser';
import Web3 from 'web3';
import fs from 'fs';
import { ecsign, toBuffer } from 'ethereumjs-util';
import { encrypt as eciesEncrypt, decrypt as eciesDecrypt } from 'eciesjs';
import { ethers } from 'ethers';
import pkg from 'elliptic';
const { ec: EC } = pkg;

// --- Constants to mimic app storage ---
const patientPrivateKey = 'PASTE_PATIENT_PRIVATE_KEY';
const patientPublicKey = 'PASTE_PATIENT_PUBLIC_KEY';
const healthId = 'PASTE_HEALTH_ID';
const encryptedSymKeyForPatient = 'PASTE_ENCRYPTED_SYM_KEY';
const ipfsHash = 'PASTE_IPFS_HASH';
const patientAddress = 'PASTE_PATIENT_ADDRESS';

const app = express();
app.use(bodyParser.json());

const web3 = new Web3('http://localhost:8548');
const abi = JSON.parse(fs.readFileSync('build/health.abi', 'utf8'));
const contract = new web3.eth.Contract(abi, healthId);

// --- Set Pseudonym ---
app.post('/set-pseudonym', async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Missing password' });
    const passwordHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(password));
    const saltBytes = ethers.utils.randomBytes(32);
    const salt = ethers.utils.hexlify(saltBytes);
    const provider = new ethers.providers.JsonRpcProvider('http://localhost:8548');
    const wallet = new ethers.Wallet(patientPrivateKey, provider);
    const ethersContract = new ethers.Contract(healthId, abi, wallet);
    const tx = await ethersContract.setPseudonym(salt, passwordHash);
    await tx.wait();
    res.json({ status: 'Pseudonym set', txHash: tx.hash, salt });
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
    res.json({ status: 'Hospital authorized', receipt });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    res.json({ status: 'Hospital revoked', receipt });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(3001, () => {
  console.log('Patient API running on port 3001');
}); 