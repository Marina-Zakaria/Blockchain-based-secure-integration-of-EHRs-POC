// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./RegistrySC.sol";

contract HealthSC {
    RegistrySC public registry;

    address public hospital;         // Hospital that deployed the contract
    address public patient;          // Patient's address
    string public patientPublicKey;  // Patient's public key (as string)
    string public ipfsHash;          // IPFS hash of medical data
    string public pseudonym;         // Patient's pseudonym
    bool public pseudonymSet;        // Flag to enforce one-time set

    mapping(address => bytes) public authorizedHospitalKeys;
    address[] public authorizedHospitalList;

    event RecordInitialized(address indexed hospital, string patientPublicKey, string pseudonym, string ipfsHash);
    event HospitalAuthorized(address indexed hospital);
    event HospitalRevoked(address indexed hospital);
    event PseudonymSet(address indexed patient, string pseudonym);
    event PseudonymReset(address indexed regulator, address indexed oldPatient, address indexed newPatient, string newPseudonym);
    event DebugHospitalAdded(address indexed hospital);
    event PIIHashUpdated(address indexed hospital, string oldIpfsHash, string newIpfsHash);
    event AuthorizedHospitalsSynced(address indexed patient, uint256 hospitalCount);

    constructor(
        address registryAddress,
        address _patient,
        string memory _patientPublicKey,
        string memory _ipfsHash,
        address hospitalAddress,
        bytes memory encryptedSymKeyForHospital
    ) {
        registry = RegistrySC(registryAddress);
        require(registry.isHospitalRegistered(msg.sender), "Not a registered hospital");
        hospital = msg.sender;
        patient = _patient;
        patientPublicKey = _patientPublicKey;
        ipfsHash = _ipfsHash;
        pseudonymSet = false;
        // Authorize the deploying hospital with its encrypted symmetric key
        authorizedHospitalKeys[hospitalAddress] = encryptedSymKeyForHospital;
        authorizedHospitalList.push(hospitalAddress);
        emit DebugHospitalAdded(hospitalAddress);
        emit RecordInitialized(hospital, patientPublicKey, "", ipfsHash);
        emit HospitalAuthorized(hospitalAddress);
    }

    // Internal: verify patient signature
    function _verifyPatient(
        bytes memory message,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal view returns (bool) {
        address signer = ecrecover(keccak256(message), v, r, s);
        return signer == patient;
    }

    // Authorize a new hospital (patient only, with signature)
    function authorizeHospital(
        address newHospital,
        bytes memory encryptedSymKey,
        bytes memory message,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(_verifyPatient(message, v, r, s), "Not authorized: invalid patient signature");
        require(registry.isHospitalRegistered(newHospital), "Hospital not registered");
        require(authorizedHospitalKeys[newHospital].length == 0, "Already authorized");
        authorizedHospitalKeys[newHospital] = encryptedSymKey;
        authorizedHospitalList.push(newHospital);
        emit DebugHospitalAdded(newHospital);
        emit HospitalAuthorized(newHospital);
    }

    // Revoke a hospital's authorization (patient only, with signature)
    function revokeHospital(
        address hospitalToRevoke,
        bytes memory message,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(_verifyPatient(message, v, r, s), "Not authorized: invalid patient signature");
        require(authorizedHospitalKeys[hospitalToRevoke].length != 0, "Hospital not authorized");
        require(authorizedHospitalList.length > 1, "At least one hospital must remain authorized");
        delete authorizedHospitalKeys[hospitalToRevoke];
        // Remove from array
        for (uint i = 0; i < authorizedHospitalList.length; i++) {
            if (authorizedHospitalList[i] == hospitalToRevoke) {
                authorizedHospitalList[i] = authorizedHospitalList[authorizedHospitalList.length - 1];
                authorizedHospitalList.pop();
                break;
            }
        }
        emit HospitalRevoked(hospitalToRevoke);
    }

    // Return the list of authorized hospitals (only callable by patient)
    function getAuthorizedHospitals(
        bytes memory message,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external view returns (address[] memory) {
        require(_verifyPatient(message, v, r, s), "Not authorized: invalid patient signature");
        return authorizedHospitalList;
    }

    // Internal: get all authorized hospital addresses
    function _authorizedHospitalAddresses() internal view returns (address[] memory) {
        uint count = getAuthorizedHospitalCount();
        address[] memory result = new address[](count);
        uint idx = 0;
        for (uint i = 0; i < 256; i++) { // up to 256 hospitals
            address possible = address(uint160(i));
            if (authorizedHospitalKeys[possible].length != 0) {
                result[idx] = possible;
                idx++;
                if (idx == count) break;
            }
        }
        return result;
    }

    // Internal: count authorized hospitals
    function getAuthorizedHospitalCount() public view returns (uint count) {
        count = 0;
        // This is a naive implementation; in production, consider a more efficient way
        for (uint i = 0; i < 256; i++) {
            address possible = address(uint160(i));
            if (authorizedHospitalKeys[possible].length != 0) {
                count++;
            }
        }
    }

    // Patient sets their pseudonym (one-time only, computed on-chain)
    function setPseudonym(bytes32 salt, bytes32 passwordHash) external {
        require(msg.sender == patient, "Only patient can set pseudonym");
        require(!pseudonymSet, "Pseudonym already set");
        pseudonym = toHexString(keccak256(abi.encodePacked(patient, salt, passwordHash)));
        pseudonymSet = true;
        emit PseudonymSet(patient, pseudonym);
    }

    // Helper to convert bytes32 to hex string
    function toHexString(bytes32 data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(64);
        for (uint i = 0; i < 32; i++) {
            str[i*2] = alphabet[uint(uint8(data[i] >> 4))];
            str[1+i*2] = alphabet[uint(uint8(data[i] & 0x0f))];
        }
        return string(str);
    }

    // Regulator can reset pseudonym and patient address (recovery)
    function resetPseudonym(address newPatient, string memory newPseudonym) external {
        require(registry.isRegulator(msg.sender), "Only regulator can reset pseudonym");
        address oldPatient = patient;
        patient = newPatient;
        pseudonym = newPseudonym;
        pseudonymSet = true;
        emit PseudonymReset(msg.sender, oldPatient, newPatient, newPseudonym);
    }

    // Retrieve pseudonym for a hospital, only via a registered gateway and with hospital signature
    function getPseudonymForHospital(
        address hospitalAddr,
        bytes memory message,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external view returns (string memory) {
        require(registry.isGateway(msg.sender), "Only a registered gateway can call this");
        address signer = ecrecover(keccak256(message), v, r, s);
        require(uint160(signer) == uint160(hospitalAddr), "Signature does not match hospital address");
        require(registry.isHospitalRegistered(hospitalAddr), "Hospital not registered");
        require(authorizedHospitalKeys[hospitalAddr].length != 0, "Hospital not authorized");
        require(pseudonymSet, "Pseudonym not set");
        return pseudonym;
    }

    // Patient can set or update the encrypted symmetric key for a hospital
    function setHospitalKey(address hospitalAddr, bytes memory encryptedSymKey) external {
        require(msg.sender == patient, "Only patient can set hospital key");
        require(registry.isHospitalRegistered(hospitalAddr), "Hospital not registered");
        authorizedHospitalKeys[hospitalAddr] = encryptedSymKey;
    }

    // Hospital can retrieve the IPFS hash and its encrypted symmetric key if authorized
    function getPIIReference() external view returns (string memory, bytes memory) {
        require(registry.isHospitalRegistered(msg.sender), "Only a registered hospital can call this");
        require(authorizedHospitalKeys[msg.sender].length != 0, "Hospital not authorized");
        return (ipfsHash, authorizedHospitalKeys[msg.sender]);
    }

    // Hospital can update the IPFS hash of patient PII (must be registered and authorized)
    function updatePIIHash(string memory newIpfsHash) external {
        require(registry.isHospitalRegistered(msg.sender), "Only a registered hospital can call this");
        require(authorizedHospitalKeys[msg.sender].length != 0, "Hospital not authorized");
        require(bytes(newIpfsHash).length > 0, "IPFS hash cannot be empty");
        
        string memory oldHash = ipfsHash;
        ipfsHash = newIpfsHash;
        emit PIIHashUpdated(msg.sender, oldHash, newIpfsHash);
    }

    // Patient can sync all authorized hospitals with new encrypted symmetric keys
    function syncAuthorizedHospitals(address[] memory hospitals, bytes[] memory encryptedKeys) external {
        require(msg.sender == patient, "Only patient can sync hospital keys");
        require(hospitals.length == encryptedKeys.length, "Arrays length mismatch");
        
        for (uint i = 0; i < hospitals.length; i++) {
            require(registry.isHospitalRegistered(hospitals[i]), "Hospital not registered");
            require(authorizedHospitalKeys[hospitals[i]].length != 0, "Hospital not authorized");
            authorizedHospitalKeys[hospitals[i]] = encryptedKeys[i];
        }
        
        emit AuthorizedHospitalsSynced(msg.sender, hospitals.length);
    }
} 