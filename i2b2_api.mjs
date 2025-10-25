import express from 'express';
import bodyParser from 'body-parser';
import pg from 'pg';
import crypto from 'crypto';
import fs from 'fs';
import { decrypt as eciesDecrypt } from 'eciesjs';
import Web3 from 'web3';
import { ecrecover, pubToAddress, toBuffer } from 'ethereumjs-util';

const { Pool } = pg;

const app = express();
const PORT = 3004;

// Increased limit for large EHR uploads
app.use(bodyParser.json({ limit: '50mb' }));

// Load DW private key for decryption
const dwKeys = JSON.parse(fs.readFileSync('dw_keys.json', 'utf8'));
const dwPrivateKey = dwKeys.dw.privateKey; // Hex string without 0x prefix

// Web3 instance for signature verification
const web3 = new Web3();

// PostgreSQL connection pool
const pool = new Pool({
  host: 'localhost',
  port: 5432,
  database: 'i2b2',
  user: 'postgres',
  password: 'demouser',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Nonce storage for replay protection (in production, use Redis)
const usedNonces = new Set();

// Logging utility
function log(level, message, context = {}) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    level,
    service: 'I2B2_API',
    message,
    ...context
  };
  console.log(JSON.stringify(logEntry, null, 2));
}

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ 
      status: 'healthy',
      service: 'i2b2-api',
      database: 'connected',
      port: PORT,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      error: error.message
    });
  }
});

// Verify and decrypt token
function verifyAndDecryptToken(token, requestId) {
  try {
    log('INFO', 'Verifying token', { requestId });
    
    // Token structure: { encryptedPayload, gatewaySignature, gatewayAddress }
    const { encryptedPayload, gatewaySignature, gatewayAddress } = token;
    
    if (!encryptedPayload || !gatewaySignature || !gatewayAddress) {
      throw new Error('Invalid token structure');
    }
    
    // Step 1: Decrypt the payload with DW's private key
    log('INFO', 'Decrypting payload', { requestId });
    const encryptedBuffer = Buffer.from(encryptedPayload.replace(/^0x/, ''), 'hex');
    const dwPrivateKeyBuffer = Buffer.from(dwPrivateKey, 'hex');
    const decryptedBuffer = eciesDecrypt(dwPrivateKeyBuffer, encryptedBuffer);
    const payloadString = decryptedBuffer.toString('utf8');
    const tokenPayload = JSON.parse(payloadString);
    
    log('INFO', 'Payload decrypted', { 
      requestId,
      payloadKeys: Object.keys(tokenPayload)
    });
    
    // TokenPayload contains:
    // - encryptedPseudonym (encrypted with DW's pk from blockchain)
    // - hospitalAddress
    // - timestamp
    // - expiry
    // - nonce
    // - healthID
    
    // Step 2: Verify gateway signature
    log('INFO', 'Verifying gateway signature', { requestId, gatewayAddress });
    const payloadHash = web3.utils.keccak256(payloadString);
    
    // Recover signer from signature
    const { v, r, s } = gatewaySignature;
    const msgBuffer = toBuffer(payloadHash);
    const vNum = typeof v === 'string' ? parseInt(v) : v;
    const rBuffer = toBuffer(r);
    const sBuffer = toBuffer(s);
    
    const publicKey = ecrecover(msgBuffer, vNum, rBuffer, sBuffer);
    const recoveredAddress = '0x' + pubToAddress(publicKey).toString('hex');
    
    if (recoveredAddress.toLowerCase() !== gatewayAddress.toLowerCase()) {
      throw new Error(`Gateway signature verification failed: expected ${gatewayAddress}, got ${recoveredAddress}`);
    }
    
    log('INFO', 'Gateway signature verified', { requestId });
    
    // Step 3: Check token expiry
    const currentTimestamp = Math.floor(Date.now() / 1000);
    if (currentTimestamp > tokenPayload.expiry) {
      throw new Error(`Token expired at ${new Date(tokenPayload.expiry * 1000).toISOString()}`);
    }
    
    log('INFO', 'Token not expired', { 
      requestId,
      expiresAt: new Date(tokenPayload.expiry * 1000).toISOString()
    });
    
    // Step 4: Check nonce for replay protection
    if (usedNonces.has(tokenPayload.nonce)) {
      throw new Error('Token nonce already used (replay attack detected)');
    }
    usedNonces.add(tokenPayload.nonce);
    
    // Clean up old nonces (keep last 10000)
    if (usedNonces.size > 10000) {
      const oldestNonces = Array.from(usedNonces).slice(0, usedNonces.size - 10000);
      oldestNonces.forEach(n => usedNonces.delete(n));
    }
    
    log('INFO', 'Nonce validated', { requestId });
    
    // Step 5: Extract the encrypted pseudonym from blockchain
    // This pseudonym is already encrypted with DW's public key
    // In the actual implementation, this would be decrypted here
    // For now, we use it directly as a patient identifier
    const pseudonym = tokenPayload.encryptedPseudonym;
    
    // Convert pseudonym to patient_num (deterministic)
    const hash = crypto.createHash('sha256').update(pseudonym).digest();
    const num = parseInt(hash.toString('hex').substring(0, 8), 16);
    const patientNum = (num % 900000) + 100000; // Range: 100000-999999
    
    log('INFO', 'Token verified successfully', { 
      requestId,
      patientNum,
      hospitalAddress: tokenPayload.hospitalAddress
    });
    
    return { patientNum, tokenPayload };
    
  } catch (error) {
    log('ERROR', 'Token verification failed', {
      requestId,
      error: error.message
    });
    throw error;
  }
}

// Upload EHR endpoint
app.post('/upload-ehr', async (req, res) => {
  const requestId = crypto.randomBytes(16).toString('hex');
  const startTime = Date.now();
  
  try {
    const { token, patientData, observations } = req.body;
    
    log('INFO', 'EHR upload request received', {
      requestId,
      hasToken: !!token,
      hasPatientData: !!patientData,
      observationCount: observations?.length || 0,
      payloadSizeKB: (JSON.stringify(req.body).length / 1024).toFixed(2)
    });

    if (!token) {
      log('ERROR', 'Missing token', { requestId });
      return res.status(400).json({ error: 'Missing token', requestId });
    }

    if (!patientData) {
      log('ERROR', 'Missing patientData', { requestId });
      return res.status(400).json({ error: 'Missing patientData', requestId });
    }

    // Verify and decrypt token
    const { patientNum, tokenPayload } = verifyAndDecryptToken(token, requestId);

    // Get database client
    const client = await pool.connect();
    
    try {
      // Insert or update patient demographics
      const patientSql = `
        INSERT INTO i2b2demodata.patient_dimension (
          patient_num, sex_cd, age_in_years_num, race_cd, 
          update_date, download_date, import_date, sourcesystem_cd
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (patient_num) DO UPDATE SET
          sex_cd = EXCLUDED.sex_cd,
          age_in_years_num = EXCLUDED.age_in_years_num,
          race_cd = EXCLUDED.race_cd,
          update_date = EXCLUDED.update_date
      `;
      
      const currentDate = new Date();
      await client.query(patientSql, [
        patientNum,
        patientData.sex_cd || 'U',
        patientData.age_in_years_num || null,
        patientData.race_cd || 'Unknown',
        currentDate,
        currentDate,
        currentDate,
        'BLOCKCHAIN_EHR'
      ]);
      
      log('INFO', 'Patient demographics updated', { requestId, patientNum });

      // Encounter number for observations
      const encounterNum = 2000 + patientNum;

      // Insert observations using CHUNKED BATCH INSERT (optimized!)
      if (observations && observations.length > 0) {
        const batchStartTime = Date.now();
        
        // PostgreSQL parameter limit: ~32,767 parameters
        // With 23 columns: 32767 / 23 = 1424 rows max. Use 1420 (95% of limit).
        const CHUNK_SIZE = 1420;
        const chunks = [];
        
        for (let i = 0; i < observations.length; i += CHUNK_SIZE) {
          chunks.push(observations.slice(i, i + CHUNK_SIZE));
        }
        
        log('INFO', `Inserting ${observations.length} observations in ${chunks.length} chunks`, {
          requestId,
          totalObs: observations.length,
          chunkCount: chunks.length,
          chunkSize: CHUNK_SIZE
        });
        
        // Wrap all chunks in a single transaction
        await client.query('BEGIN');
        
        try {
          for (const [chunkIndex, chunk] of chunks.entries()) {
            const chunkStartTime = Date.now();
            const valuePlaceholders = [];
            const allValues = [];
            let paramIndex = 1;
            
            chunk.forEach((obs) => {
              const placeholders = [];
              for (let i = 0; i < 23; i++) {
                placeholders.push(`$${paramIndex++}`);
              }
              valuePlaceholders.push(`(${placeholders.join(', ')})`);
              
              allValues.push(
                encounterNum,
                patientNum,
                obs.concept_cd || 'UNKNOWN:UNKNOWN',
                obs.provider_id || 'PROVIDER001',
                obs.start_date || currentDate,
                obs.modifier_cd || '@',
                obs.instance_num || 1,
                obs.valtype_cd || 'T',
                obs.tval_char || '',
                obs.nval_num || null,
                obs.valueflag_cd || 'E',
                obs.quantity_num || 1,
                obs.units_cd || null,
                obs.start_date || currentDate,
                'CLINIC',
                null,
                1,
                currentDate,
                currentDate,
                currentDate,
                'BLOCKCHAIN_EHR',
                1,
                1
              );
            });
            
            const batchObsSql = `
              INSERT INTO i2b2demodata.observation_fact (
                encounter_num, patient_num, concept_cd, provider_id, start_date,
                modifier_cd, instance_num, valtype_cd, tval_char, nval_num,
                valueflag_cd, quantity_num, units_cd, end_date, location_cd,
                observation_blob, confidence_num, update_date, download_date,
                import_date, sourcesystem_cd, upload_id, text_search_index
              ) VALUES ${valuePlaceholders.join(', ')}
            `;
            
            await client.query(batchObsSql, allValues);
            
            const chunkTime = Date.now() - chunkStartTime;
            log('INFO', `Chunk ${chunkIndex + 1}/${chunks.length} inserted`, {
              requestId,
              chunkRows: chunk.length,
              chunkTimeMs: chunkTime
            });
          }
          
          await client.query('COMMIT');
          
        } catch (error) {
          await client.query('ROLLBACK');
          throw error;
        }
        
        const batchTime = Date.now() - batchStartTime;
        
        log('INFO', 'All observations uploaded (CHUNKED BATCH INSERT)', { 
          requestId,
          patientNum,
          observationCount: observations.length,
          chunks: chunks.length,
          batchTimeMs: batchTime
        });
      }

      const totalTime = Date.now() - startTime;
      
      log('INFO', 'EHR upload completed successfully', { 
        requestId,
        patientNum,
        recordsUploaded: observations?.length || 0,
        totalTimeMs: totalTime,
        authorizedHospital: tokenPayload.hospitalAddress
      });

      res.json({
        status: 'success',
        message: 'EHR data uploaded successfully',
        patientNum,
        recordsUploaded: observations?.length || 0,
        requestId,
        processingTimeMs: totalTime
      });

    } finally {
      client.release();
    }

  } catch (error) {
    const totalTime = Date.now() - startTime;
    
    log('ERROR', 'EHR upload failed', {
      requestId,
      error: error.message,
      stack: error.stack,
      totalTimeMs: totalTime
    });

    res.status(500).json({
      status: 'error',
      error: error.message,
      requestId
    });
  }
});

// Download EHR endpoint
app.post('/download-ehr', async (req, res) => {
  const requestId = crypto.randomBytes(16).toString('hex');
  const startTime = Date.now();
  
  try {
    const { token } = req.body;
    
    log('INFO', 'EHR download request received', {
      requestId,
      hasToken: !!token
    });

    if (!token) {
      log('ERROR', 'Missing token', { requestId });
      return res.status(400).json({ error: 'Missing token', requestId });
    }

    // Verify and decrypt token
    const { patientNum, tokenPayload } = verifyAndDecryptToken(token, requestId);

    const client = await pool.connect();
    
    try {
      // Get patient demographics
      const patientSql = `
        SELECT patient_num, sex_cd, age_in_years_num, race_cd, 
               update_date, sourcesystem_cd
        FROM i2b2demodata.patient_dimension
        WHERE patient_num = $1
      `;
      
      const patientResult = await client.query(patientSql, [patientNum]);
      
      if (patientResult.rows.length === 0) {
        log('WARN', 'Patient not found', { requestId, patientNum });
        return res.status(404).json({
          status: 'error',
          error: 'Patient not found',
          requestId
        });
      }
      
      const patientData = patientResult.rows[0];
      log('INFO', 'Patient demographics retrieved', { requestId, patientNum });

      // Get observations
      const obsSql = `
        SELECT concept_cd, provider_id, start_date, modifier_cd, instance_num,
               valtype_cd, tval_char, nval_num, valueflag_cd, quantity_num,
               units_cd, end_date, location_cd, update_date
        FROM i2b2demodata.observation_fact
        WHERE patient_num = $1
        ORDER BY start_date DESC, concept_cd
      `;
      
      const obsResult = await client.query(obsSql, [patientNum]);
      const observations = obsResult.rows;
      
      log('INFO', 'Observations retrieved', { 
        requestId, 
        patientNum,
        observationCount: observations.length,
        authorizedHospital: tokenPayload.hospitalAddress
      });

      const totalTime = Date.now() - startTime;

      res.json({
        status: 'success',
        patientData,
        observations,
        recordCount: observations.length,
        requestId,
        processingTimeMs: totalTime
      });

    } finally {
      client.release();
    }

  } catch (error) {
    const totalTime = Date.now() - startTime;
    
    log('ERROR', 'EHR download failed', {
      requestId,
      error: error.message,
      stack: error.stack,
      totalTimeMs: totalTime
    });

    res.status(500).json({
      status: 'error',
      error: error.message,
      requestId
    });
  }
});

// Start server
app.listen(PORT, () => {
  log('INFO', 'i2b2 Data Warehouse API started', {
    port: PORT,
    database: 'i2b2',
    host: 'localhost:5432',
    dwPublicKey: dwKeys.dw.publicKey.substring(0, 20) + '...',
    optimizations: [
      'Token decryption with DW private key',
      'Gateway signature verification',
      'Nonce replay protection',
      'Token expiry validation',
      'Chunked batch inserts (1420 rows/chunk)',
      'Transaction wrapping',
      '50MB payload limit'
    ]
  });
  console.log(`✅ i2b2 DW API running on port ${PORT}`);
  console.log(`✅ Database: localhost:5432/i2b2`);
  console.log(`✅ DW Private Key loaded for decryption`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  log('INFO', 'SIGTERM received, closing connections');
  await pool.end();
  process.exit(0);
});

process.on('SIGINT', async () => {
  log('INFO', 'SIGINT received, closing connections');
  await pool.end();
  process.exit(0);
});
