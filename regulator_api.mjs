import express from 'express';
import bodyParser from 'body-parser';
import Web3 from 'web3';
import fs from 'fs';

const app = express();
app.use(bodyParser.json());

// --- Constants (update as needed) ---
const rpcUrl = 'http://localhost:8545';
const registryAddress = '0x3eDADD129Feb03a23D978B45F87964aFe8BEB054'; // or as in your scripts
const from = '0xfff54c8a4cf2bb7257ccbcf7c63b36d839bcf3d7'; // regulator account
const password = fs.readFileSync('password.txt', 'utf8').trim();
const abi = JSON.parse(fs.readFileSync('build/registry.abi', 'utf8'));

const web3 = new Web3(rpcUrl);
const contract = new web3.eth.Contract(abi, registryAddress);

// --- Add Regulator ---
app.post('/add-regulator', async (req, res) => {
  try {
    const { regulatorAddress } = req.body;
    if (!regulatorAddress) return res.status(400).json({ error: 'Missing regulatorAddress' });
    await web3.eth.personal.unlockAccount(from, password, 600);
    await contract.methods.addRegulator(regulatorAddress)
      .send({ from, gas: 300000, gasPrice: '0' })
      .on('receipt', receipt => res.json({ status: 'Regulator added', receipt }))
      .on('error', err => res.status(500).json({ error: err.message }));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Register Hospital ---
app.post('/register-hospital', async (req, res) => {
  try {
    const { hospitalAddress, hospitalPublicKey } = req.body;
    if (!hospitalAddress || !hospitalPublicKey) return res.status(400).json({ error: 'Missing hospitalAddress or hospitalPublicKey' });
    await web3.eth.personal.unlockAccount(from, password, 600);
    await contract.methods.registerHospital(hospitalAddress, hospitalPublicKey)
      .send({ from, gas: 300000, gasPrice: '0' })
      .on('receipt', receipt => res.json({ status: 'Hospital registered', receipt }))
      .on('error', err => res.status(500).json({ error: err.message }));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Deregister Hospital ---
app.post('/deregister-hospital', async (req, res) => {
  try {
    const { hospitalAddress } = req.body;
    if (!hospitalAddress) return res.status(400).json({ error: 'Missing hospitalAddress' });
    await web3.eth.personal.unlockAccount(from, password, 600);
    await contract.methods.deregisterHospital(hospitalAddress)
      .send({ from, gas: 300000, gasPrice: '0' })
      .on('receipt', receipt => res.json({ status: 'Hospital deregistered', receipt }))
      .on('error', err => res.status(500).json({ error: err.message }));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Register Doctor ---
app.post('/register-doctor', async (req, res) => {
  try {
    const { doctorAddress } = req.body;
    if (!doctorAddress) return res.status(400).json({ error: 'Missing doctorAddress' });
    await web3.eth.personal.unlockAccount(from, password, 600);
    await contract.methods.registerDoctor(doctorAddress)
      .send({ from, gas: 300000, gasPrice: '0' })
      .on('receipt', receipt => res.json({ status: 'Doctor registered', receipt }))
      .on('error', err => res.status(500).json({ error: err.message }));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Deregister Doctor ---
app.post('/deregister-doctor', async (req, res) => {
  try {
    const { doctorAddress } = req.body;
    if (!doctorAddress) return res.status(400).json({ error: 'Missing doctorAddress' });
    await web3.eth.personal.unlockAccount(from, password, 600);
    await contract.methods.deregisterDoctor(doctorAddress)
      .send({ from, gas: 300000, gasPrice: '0' })
      .on('receipt', receipt => res.json({ status: 'Doctor deregistered', receipt }))
      .on('error', err => res.status(500).json({ error: err.message }));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Register Gateway ---
app.post('/register-gateway', async (req, res) => {
  try {
    const { gatewayAddress } = req.body;
    if (!gatewayAddress) return res.status(400).json({ error: 'Missing gatewayAddress' });
    await web3.eth.personal.unlockAccount(from, password, 600);
    await contract.methods.addGateway(gatewayAddress)
      .send({ from, gas: 300000, gasPrice: '0' })
      .on('receipt', receipt => res.json({ status: 'Gateway registered', receipt }))
      .on('error', err => res.status(500).json({ error: err.message }));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Registry List ---
app.get('/registry-list', async (req, res) => {
  try {
    // Get all events from block 0
    const [hospitalAdded, hospitalRemoved, doctorAdded, doctorRemoved, regulatorAdded, regulatorRemoved, gatewayAdded, gatewayRemoved] = await Promise.all([
      contract.getPastEvents('HospitalRegistered', { fromBlock: 0, toBlock: 'latest' }),
      contract.getPastEvents('HospitalDeregistered', { fromBlock: 0, toBlock: 'latest' }),
      contract.getPastEvents('DoctorRegistered', { fromBlock: 0, toBlock: 'latest' }),
      contract.getPastEvents('DoctorDeregistered', { fromBlock: 0, toBlock: 'latest' }),
      contract.getPastEvents('RegulatorAdded', { fromBlock: 0, toBlock: 'latest' }),
      contract.getPastEvents('RegulatorRemoved', { fromBlock: 0, toBlock: 'latest' }),
      contract.getPastEvents('GatewayAdded', { fromBlock: 0, toBlock: 'latest' }),
      contract.getPastEvents('GatewayRemoved', { fromBlock: 0, toBlock: 'latest' })
    ]);
    function getCurrentSet(addedEvents, removedEvents, keyName) {
      const added = new Set(addedEvents.map(e => e.returnValues[keyName].toLowerCase()));
      const removed = new Set(removedEvents.map(e => e.returnValues[keyName].toLowerCase()));
      return Array.from(added).filter(addr => !removed.has(addr));
    }
    const hospitals = getCurrentSet(hospitalAdded, hospitalRemoved, 'hospitalAddress');
    const doctors = getCurrentSet(doctorAdded, doctorRemoved, 'doctorAddress');
    const regulators = getCurrentSet(regulatorAdded, regulatorRemoved, 'regulatorAddress');
    const gateways = getCurrentSet(gatewayAdded, gatewayRemoved, 'gateway');
    res.json({ hospitals, doctors, regulators, gateways });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(3003, () => {
  console.log('Regulator API running on port 3003');
}); 