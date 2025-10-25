import express from 'express';
import bodyParser from 'body-parser';
import Web3 from 'web3';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import { encrypt as eciesEncrypt } from 'eciesjs';
import { ecsign, toBuffer } from 'ethereumjs-util';

const app = express();
app.use(bodyParser.json());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const registryAddress = '0x9923fFb3d17Afa87B2Ec53833648f503a4ef7980'; // Update as needed
const web3 = new Web3('http://localhost:8549'); // Gateway node RPC
const abi = JSON.parse(fs.readFileSync(path.join(__dirname, 'build/health.abi'), 'utf8'));
const registryAbi = JSON.parse(fs.readFileSync(path.join(__dirname, 'build/registry.abi'), 'utf8'));

// Load Data Warehouse keys
const dwKeys = JSON.parse(fs.readFileSync(path.join(__dirname, 'dw_keys.json'), 'utf8'));
const dwPublicKey = dwKeys.dw.publicKey; // Uncompressed public key (130 hex chars, no 0x prefix)

// Gateway's private key for signing tokens
const gatewayPrivateKey = fs.readFileSync(path.join(__dirname, 'node5_private_key.txt'), 'utf8').trim();
const gatewayAddress = '0x666488aF0085F8e2c7DD38943ED3797cf11845c2';
// Derive the address from the loaded private key to ensure signing key matches configured address
const derivedGatewayAddress = new Web3().eth.accounts.privateKeyToAccount('0x' + gatewayPrivateKey).address;

// Nonce storage for replay attack prevention (in production, use Redis or database)
const usedNonces = new Set();

// Helper to generate unique nonce
function generateNonce() {
  return crypto.randomBytes(32).toString('hex');
}

// Helper to log with timestamp
function log(level, message, data = {}) {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    level,
    service: 'GATEWAY_API',
    message,
    ...data
  };
  console.log(JSON.stringify(logEntry, null, 2));
}

app.post('/get-pseudonym-for-hospital', async (req, res) => {
  const requestId = crypto.randomBytes(16).toString('hex');
  
  try {
    const { healthID, hospitalAddress, timestamp, nonce, message, messageHash, signature } = req.body;
    
    log('INFO', 'Received token request', { 
      requestId, 
      healthID, 
      hospitalAddress,
      timestamp,
      nonce: nonce ? nonce.substring(0, 16) + '...' : undefined,
      messageLength: message ? message.length : 0
    });
    
    // Validate required fields
    if (!healthID || !hospitalAddress || !timestamp || !nonce || !message || !signature) {
      log('ERROR', 'Missing required fields', { requestId });
      return res.status(400).json({ 
        error: 'Missing required fields: healthID, hospitalAddress, timestamp, nonce, message, signature',
        requestId 
      });
    }
    
    if (!signature.v || !signature.r || !signature.s) {
      log('ERROR', 'Invalid signature structure', { requestId });
      return res.status(400).json({ error: 'Invalid signature structure', requestId });
    }
    
    const contract = new web3.eth.Contract(abi, healthID);

    log('INFO', 'Processing token request', { 
      requestId, 
      gatewayAddress,
      derivedGatewayAddress,
      hospitalAddress 
    });

    // Note: All checks (gateway registered, hospital registered, hospital authorized)
    // are enforced by the HealthSC.getPseudonymForHospital() function.
    // If any check fails, the smart contract will revert with a specific error.

    // Step 5: Fetch encrypted pseudonym from blockchain
    // This call to getPseudonymForHospital() automatically enforces ALL checks:
    // - Gateway is registered (via msg.sender check)
    // - Hospital is registered
    // - Hospital is authorized by patient
    // - Pseudonym is set
    // - Hospital signature is valid (contract will hash message and verify)
    let encryptedPseudonym;
    try {
      encryptedPseudonym = await contract.methods.getPseudonymForHospital(
        hospitalAddress,
        message,        // Unhashed message (contract will hash it)
        signature.v,
        signature.r,
        signature.s
      ).call({ from: gatewayAddress });
      
      log('INFO', 'Encrypted pseudonym retrieved (all checks passed)', { 
        requestId,
        encryptedPseudonymLength: encryptedPseudonym.length
      });
    } catch (pseudonymError) {
      // Smart contract will revert with specific error messages:
      // - "Only a registered gateway can call this"
      // - "Hospital not registered"
      // - "Hospital not authorized"
      // - "Pseudonym not set"
      // - "Signature does not match hospital address"
      
      // Extract detailed error information
      const errorDetails = {
        message: pseudonymError.message,
        data: pseudonymError.data,
        reason: pseudonymError.reason,
        code: pseudonymError.code,
        innerError: pseudonymError.innerError?.message
      };
      
      log('ERROR', 'Smart contract check failed', { 
        requestId,
        ...errorDetails,
        healthID,
        hospitalAddress,
        gatewayAddress
      });
      
      // Try to extract revert reason
      let errorMessage = 'Authorization failed';
      if (pseudonymError.message.includes('Only a registered gateway')) {
        errorMessage = 'Gateway not registered in RegistrySC';
      } else if (pseudonymError.message.includes('Hospital not registered')) {
        errorMessage = 'Hospital not registered in RegistrySC';
      } else if (pseudonymError.message.includes('Hospital not authorized')) {
        errorMessage = 'Hospital not authorized by patient';
      } else if (pseudonymError.message.includes('Pseudonym not set')) {
        errorMessage = 'Patient has not set pseudonym yet';
      } else if (pseudonymError.message.includes('Signature')) {
        errorMessage = 'Hospital signature verification failed';
      } else {
        errorMessage = pseudonymError.message;
      }
      
      return res.status(403).json({ 
        error: errorMessage,
        details: errorDetails,
        requestId 
      });
    }

    // Step 6: Generate token components
    const tokenTimestamp = Math.floor(Date.now() / 1000); // Unix timestamp in seconds
    const tokenExpiry = tokenTimestamp + (60 * 60); // 1 hour expiration
    const tokenNonce = generateNonce();

    log('INFO', 'Token components generated', { 
      requestId,
      tokenTimestamp,
      tokenExpiry,
      expiresIn: '3600 seconds (1 hour)',
      tokenNonce
    });

    // Step 7: Construct TokenPayload
    // TokenPayload = { encrypted pseudonym, HospitalH, ts, expiry, nonce }
    const tokenPayload = {
      encryptedPseudonym: encryptedPseudonym,  // Already encrypted with DW's pk from blockchain
      hospitalAddress: hospitalAddress,         // Hospital H
      timestamp: tokenTimestamp,                // Token generation time
      expiry: tokenExpiry,                      // Token expiration
      nonce: tokenNonce,                        // Token nonce (different from request nonce)
      requestNonce: nonce,                      // Original request nonce for audit
      requestTimestamp: timestamp,              // Original request timestamp
      hospitalSignature: {                      // Hospital's signature σH from request
        messageHash: messageHash,
        v: signature.v,
        r: signature.r,
        s: signature.s
      },
      healthID: healthID                        // For reference
    };

    log('INFO', 'TokenPayload constructed', { 
      requestId,
      payloadKeys: Object.keys(tokenPayload)
    });

    // Step 7: Serialize TokenPayload
    const payloadString = JSON.stringify(tokenPayload);
    const payloadBuffer = Buffer.from(payloadString, 'utf8');

    // Step 8: Encrypt TokenPayload with DW's public key
    // Enc_pkDW(TokenPayload)
    const dwPubKeyBuffer = Buffer.from(dwPublicKey.replace(/^0x/, ''), 'hex');
    const encryptedPayload = eciesEncrypt(dwPubKeyBuffer, payloadBuffer);
    const encryptedPayloadHex = '0x' + encryptedPayload.toString('hex');

    log('INFO', 'TokenPayload encrypted with DW public key', { 
      requestId,
      encryptedLength: encryptedPayloadHex.length
    });

    // Step 9: Sign TokenPayload with Gateway's private key
    // Sign_skG(TokenPayload)
    const payloadHash = web3.utils.keccak256(payloadString);
    const { v: gV, r: gR, s: gS } = ecsign(
      toBuffer(payloadHash),
      toBuffer('0x' + gatewayPrivateKey)
    );

    const gatewaySignature = {
      v: gV,
      r: '0x' + gR.toString('hex'),
      s: '0x' + gS.toString('hex')
    };

    log('INFO', 'TokenPayload signed by gateway', { 
      requestId,
      signatureR: gatewaySignature.r.substring(0, 10) + '...'
    });

    // Step 10: Construct final token
    // Token = Enc_pkDW(TokenPayload) || Sign_skG(TokenPayload)
    const token = {
      encryptedPayload: encryptedPayloadHex,
      gatewaySignature: gatewaySignature,
      gatewayAddress: gatewayAddress
    };

    log('INFO', 'Token generation successful', { 
      requestId,
      hospitalAddress,
      healthID,
      tokenSize: JSON.stringify(token).length + ' bytes'
    });

    res.json({ 
      token,
      metadata: {
        issuedAt: tokenTimestamp,
        expiresAt: tokenExpiry,
        validFor: '1 hour',
        requestId
      }
    });

  } catch (error) {
    log('ERROR', 'Token generation failed', { 
      requestId,
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({ 
      error: error.message,
      requestId 
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    service: 'gateway_api',
    timestamp: new Date().toISOString()
  });
});

const PORT = 3002;
app.listen(PORT, () => {
  log('INFO', 'Gateway API started', { 
    port: PORT,
    gatewayAddress,
    derivedGatewayAddress,
    registryAddress,
    dwPublicKeyLoaded: !!dwPublicKey,
    rpcEndpoint: 'http://localhost:8549'
  });
  console.log(`✅ Gateway API running on port ${PORT}`);
  console.log(`✅ Gateway Address: ${gatewayAddress}`);
  console.log(`✅ DW Public Key: ${dwPublicKey.substring(0, 20)}...`);
});
