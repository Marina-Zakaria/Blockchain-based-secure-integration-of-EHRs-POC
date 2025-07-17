pragma solidity ^0.8.0;

contract RegistrySC {
    // Mapping of regulator addresses
    mapping(address => bool) public regulators;
    // Mapping of registered hospitals
    mapping(address => bool) public registeredHospitals;
    // Mapping of hospital public keys
    mapping(address => string) public hospitalPublicKeys;
    // Mapping of registered doctors
    mapping(address => bool) public registeredDoctors;
    // Gateway management
    mapping(address => bool) public gateways;

    // Events
    event RegulatorAdded(address regulatorAddress);
    event RegulatorRemoved(address regulatorAddress);
    event HospitalRegistered(address hospitalAddress);
    event HospitalDeregistered(address hospitalAddress);
    event DoctorRegistered(address doctorAddress);
    event DoctorDeregistered(address doctorAddress);
    event GatewayAdded(address gateway);
    event GatewayRemoved(address gateway);

    // Constructor: Set the deployer as the first regulator
    constructor() {
        regulators[msg.sender] = true;
        emit RegulatorAdded(msg.sender);
    }

    // Modifier: Only a regulator can call
    modifier onlyRegulator() {
        require(regulators[msg.sender], "Only a regulator can perform this action.");
        _;
    }

    // Add a new regulator
    function addRegulator(address regulatorAddress) public onlyRegulator {
        regulators[regulatorAddress] = true;
        emit RegulatorAdded(regulatorAddress);
    }

    // Remove a regulator
    function removeRegulator(address regulatorAddress) public onlyRegulator {
        regulators[regulatorAddress] = false;
        emit RegulatorRemoved(regulatorAddress);
    }

    // Register a hospital
    function registerHospital(address hospitalAddress, string memory publicKey) public onlyRegulator {
        registeredHospitals[hospitalAddress] = true;
        hospitalPublicKeys[hospitalAddress] = publicKey;
        emit HospitalRegistered(hospitalAddress);
    }

    // Deregister a hospital
    function deregisterHospital(address hospitalAddress) public onlyRegulator {
        registeredHospitals[hospitalAddress] = false;
        emit HospitalDeregistered(hospitalAddress);
    }

    // Register a doctor
    function registerDoctor(address doctorAddress) public onlyRegulator {
        registeredDoctors[doctorAddress] = true;
        emit DoctorRegistered(doctorAddress);
    }

    // Deregister a doctor
    function deregisterDoctor(address doctorAddress) public onlyRegulator {
        registeredDoctors[doctorAddress] = false;
        emit DoctorDeregistered(doctorAddress);
    }

    // Check if a hospital is registered
    function isHospitalRegistered(address hospitalAddress) public view returns (bool) {
        return registeredHospitals[hospitalAddress];
    }

    // Check if a doctor is registered
    function isDoctorRegistered(address doctorAddress) public view returns (bool) {
        return registeredDoctors[doctorAddress];
    }

    // Check if an address is a regulator
    function isRegulator(address regulatorAddress) public view returns (bool) {
        return regulators[regulatorAddress];
    }

    // Add a new gateway
    function addGateway(address gateway) public onlyRegulator {
        gateways[gateway] = true;
        emit GatewayAdded(gateway);
    }

    // Remove a gateway
    function removeGateway(address gateway) public onlyRegulator {
        gateways[gateway] = false;
        emit GatewayRemoved(gateway);
    }

    // Check if an address is a gateway
    function isGateway(address addr) public view returns (bool) {
        return gateways[addr];
    }

    // Get a hospital's public key
    function getHospitalPublicKey(address hospitalAddress) public view returns (string memory) {
        require(registeredHospitals[hospitalAddress], "Hospital not registered");
        return hospitalPublicKeys[hospitalAddress];
    }
}
