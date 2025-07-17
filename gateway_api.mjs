import express from 'express';
import bodyParser from 'body-parser';
import Web3 from 'web3';
import fs from 'fs';
import { ecsign, toBuffer } from 'ethereumjs-util';

const app = express();
app.use(bodyParser.json());

const registryAddress = '0xa0fae6861F7De028b94b3Ef2bd1Fb51E25E203ea'; // Update as needed
const web3 = new Web3('http://localhost:8547'); // Gateway node RPC
const abi = JSON.parse(fs.readFileSync('build/health.abi', 'utf8'));
const registryAbi = JSON.parse(fs.readFileSync('build/registry.abi', 'utf8'));

app.post('/get-pseudonym-for-hospital', async (req, res) => {
  try {
    const { healthID, hospitalAddress, message, v, r, s } = req.body;
    if (!healthID || !hospitalAddress || !message || v === undefined || !r || !s) {
      return res.status(400).json({ error: 'Missing healthID, hospitalAddress, message, v, r, or s' });
    }
    const contract = new web3.eth.Contract(abi, healthID);
    const registryContract = new web3.eth.Contract(registryAbi, registryAddress);
    const accounts = await web3.eth.getAccounts();
    const gatewayAddress = accounts[0];

    // Pre-flight checks
    const isGateway = await registryContract.methods.isGateway(gatewayAddress).call();
    if (!isGateway) {
      return res.status(403).json({ error: 'Gateway is not registered in RegistrySC' });
    }
    const isHospitalRegistered = await registryContract.methods.isHospitalRegistered(hospitalAddress).call();
    if (!isHospitalRegistered) {
      return res.status(403).json({ error: 'Hospital is not registered in RegistrySC' });
    }
    // Optional: check if hospital is authorized (if method exists)
    // const isHospitalAuthorized = await contract.methods.isHospitalAuthorized(hospitalAddress).call();
    // if (!isHospitalAuthorized) {
    //   return res.status(403).json({ error: 'Hospital is not authorized for this patient' });
    // }

    // Call the contract with the provided signature
    const pseudonym = await contract.methods.getPseudonymForHospital(
      hospitalAddress,
      message,
      v,
      r,
      s
    ).call({ from: gatewayAddress });

    res.json({ pseudonym });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(3002, () => {
  console.log('Gateway API running on port 3002');
}); 