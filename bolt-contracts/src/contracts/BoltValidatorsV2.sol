// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {BLS12381} from "../lib/bls/BLS12381.sol";
import {BLSSignatureVerifier} from "../lib/bls/BLSSignatureVerifier.sol";
import {IBoltValidatorsV2} from "../interfaces/IBoltValidatorsV2.sol";
import {IBoltParametersV1} from "../interfaces/IBoltParametersV1.sol";

/// @title Bolt Validators
/// @notice This contract is responsible for registering validators and managing their configuration
/// @dev This contract is upgradeable using the UUPSProxy pattern. Storage layout remains fixed across upgrades
/// with the use of storage gaps.
/// See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
/// To validate the storage layout, use the Openzeppelin Foundry Upgrades toolkit.
/// You can also validate manually with forge: forge inspect <contract> storage-layout --pretty
contract BoltValidatorsV2 is IBoltValidatorsV2, BLSSignatureVerifier, OwnableUpgradeable, UUPSUpgradeable {
    using BLS12381 for BLS12381.G1Point;

    // ========= STORAGE =========

    /// @notice Bolt Parameters contract.
    IBoltParametersV1 public parameters;

    /// @notice Validators (aka Blockspace providers)
    /// @dev Validators are blockspace providers for commitments.
    ///
    /// Validators in this mapping are identified by their sequence number.
    /// The sequence number is an incremental index assigned to each validator
    /// in the registry and is guaranteed to be unique.
    mapping(uint32 => _Validator) internal VALIDATORS;

    /// @notice Mapping of BLS public key hash to the sequence number of the validator 
    /// in the VALIDATORS mapping. This mapping is used to quickly lookup a validator
    /// by its BLS public key hash without iterating over the VALIDATORS mapping.
    mapping(bytes20 => uint32) internal validatorPubkeyHashToSequenceNumber;

    /// @notice Sequence number of the next validator to be registered
    uint32 internal nextValidatorSequenceNumber;

    /// @notice Mapping of controller index to its address. A controller map is 
    /// used to identify entities with a 32-bit index instead of their full address.
    mapping(uint32 => address) internal controllerIndexToAddress;
    mapping(address => uint32) internal controllerAddressToIndex;
    uint32 internal nextControllerIndex;

    /// @notice Mapping of authorized operator index to its address. An authorized operator map is
    /// used to identify entities with a 32-bit index instead of their full address.
    mapping(uint32 => address) internal authorizedOperatorIndexToAddress;
    mapping(address => uint32) internal authorizedOperatorToIndex;
    uint32 internal nextAuthorizedOperatorIndex;

    // TODO: adjust
    // --> Storage layout marker: 4 slots

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     * This can be validated with the Openzeppelin Foundry Upgrades toolkit.
     *
     * Total storage slots: 50
     */
    uint256[46] private __gap;

    // ========= EVENTS =========

    /// @notice Emitted when a validator is registered
    /// @param pubkeyHash BLS public key hash of the validator
    event ValidatorRegistered(bytes32 indexed pubkeyHash, uint32 indexed sequenceNumber);

    // ========= INITIALIZER =========

    /// @notice Initializer
    /// @param _owner Address of the owner of the contract
    /// @param _parameters Address of the Bolt Parameters contract
    function initialize(address _owner, address _parameters) public initializer {
        __Ownable_init(_owner);

        parameters = IBoltParametersV1(_parameters);
    }

    function initializeV2(address _owner, address _parameters) public reinitializer(2) {
        __Ownable_init(_owner);

        parameters = IBoltParametersV1(_parameters);
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    // ========= VIEW FUNCTIONS =========

    /// @notice Get all validators
    /// @dev This function should be used with caution as it can return a large amount of data.
    /// @return Validator[] memory Array of validator structs
    function getAllValidators() public view returns (ValidatorInfo[] memory) {
        uint32 validatorCount = nextValidatorSequenceNumber;
        ValidatorInfo[] memory validators = new ValidatorInfo[](validatorCount);
        for (uint32 i = 0; i < validatorCount; i++) {
            validators[i] = _getValidatorInfo(VALIDATORS[i]);
        }
        return validators;
    }

    /// @notice Get a validator by its BLS public key
    /// @param pubkey BLS public key of the validator
    /// @return Validator memory Validator struct
    function getValidatorByPubkey(
        BLS12381.G1Point calldata pubkey
    ) public view returns (ValidatorInfo memory) {
        return getValidatorByPubkeyHash(hashPubkey(pubkey));
    }

    /// @notice Get a validator by its BLS public key hash
    /// @param pubkeyHash BLS public key hash of the validator
    /// @return Validator memory Validator struct
    function getValidatorByPubkeyHash(
        bytes20 pubkeyHash
    ) public view returns (ValidatorInfo memory) {
        uint32 sequenceNumber = validatorPubkeyHashToSequenceNumber[pubkeyHash];
        _Validator memory _val = VALIDATORS[sequenceNumber];
        if (_val.pubkeyHash == bytes20(0)) {
            revert ValidatorDoesNotExist();
        }
        return _getValidatorInfo(_val);
    }

    /// @notice Get a validator by its sequence number
    /// @param sequenceNumber Sequence number of the validator
    /// @return Validator memory Validator struct
    function getValidatorBySequenceNumber(
        uint32 sequenceNumber
    ) public view returns (ValidatorInfo memory) {
        _Validator memory _val = VALIDATORS[sequenceNumber];
        if (_val.pubkeyHash == bytes20(0)) {
            revert ValidatorDoesNotExist();
        }
        return _getValidatorInfo(_val);
    }

    // ========= REGISTRATION LOGIC =========

    /// @notice Register a single Validator and authorize a Collateral Provider and Operator for it
    /// @dev This function allows anyone to register a single Validator. We do not perform any checks.
    /// @param pubkeyHash BLS public key hash for the Validator to be registered
    /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
    /// @param authorizedOperator The address of the authorized operator
    function registerValidatorUnsafe(
        bytes20 pubkeyHash,
        uint32 maxCommittedGasLimit,
        address authorizedOperator
    ) public {
        if (!parameters.ALLOW_UNSAFE_REGISTRATION()) {
            revert UnsafeRegistrationNotAllowed();
        }

        _registerValidator(pubkeyHash, authorizedOperator, maxCommittedGasLimit);
    }

    /// @notice Register a single Validator and authorize an Operator for it.
    /// @dev This function allows anyone to register a single Validator. We perform an important check:
    /// The owner of the Validator (controller) must have signed the message with its BLS private key.
    ///
    /// Message format: `chainId || controller || sequenceNumber`
    /// @param pubkey BLS public key for the Validator to be registered
    /// @param signature BLS signature of the registration message for the Validator
    /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
    /// @param authorizedOperator The address of the authorized operator
    function registerValidator(
        BLS12381.G1Point calldata pubkey,
        BLS12381.G2Point calldata signature,
        uint32 maxCommittedGasLimit,
        address authorizedOperator
    ) public {
        bytes memory message = abi.encodePacked(block.chainid, msg.sender, nextValidatorSequenceNumber);
        if (!_verifySignature(message, signature, pubkey)) {
            revert InvalidBLSSignature();
        }

        _registerValidator(hashPubkey(pubkey), authorizedOperator, maxCommittedGasLimit);
    }

    /// @notice Register a batch of Validators and authorize a Collateral Provider and Operator for them
    /// @dev This function allows anyone to register a list of Validators.
    /// @param pubkeys List of BLS public keys for the Validators to be registered
    /// @param signature BLS aggregated signature of the registration message for this batch of Validators
    /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
    /// @param authorizedOperator The address of the authorized operator
    function batchRegisterValidators(
        BLS12381.G1Point[] calldata pubkeys,
        BLS12381.G2Point calldata signature,
        uint32 maxCommittedGasLimit,
        address authorizedOperator
    ) public {
        uint32[] memory expectedValidatorSequenceNumbers = new uint32[](pubkeys.length);
        for (uint32 i = 0; i < pubkeys.length; i++) {
            expectedValidatorSequenceNumbers[i] = nextValidatorSequenceNumber + i;
        }

        // Reconstruct the unique message for which we expect an aggregated signature.
        // We need the msg.sender to prevent a front-running attack by an EOA that may
        // try to register the same validators
        bytes memory message = abi.encodePacked(block.chainid, msg.sender, expectedValidatorSequenceNumbers);

        // Aggregate the pubkeys into a single pubkey to verify the aggregated signature once
        BLS12381.G1Point memory aggPubkey = _aggregatePubkeys(pubkeys);

        if (!_verifySignature(message, signature, aggPubkey)) {
            revert InvalidBLSSignature();
        }

        bytes20[] memory pubkeyHashes = new bytes20[](pubkeys.length);
        for (uint256 i = 0; i < pubkeys.length; i++) {
            pubkeyHashes[i] = hashPubkey(pubkeys[i]);
        }

        _batchRegisterValidators(pubkeyHashes, authorizedOperator, maxCommittedGasLimit);
    }

    /// @notice Register a batch of Validators and authorize a Collateral Provider and Operator for them
    /// @dev This function allows anyone to register a list of Validators.
    /// @param pubkeyHashes List of BLS public key hashes for the Validators to be registered
    /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
    /// @param authorizedOperator The address of the authorized operator
    function batchRegisterValidatorsUnsafe(
        bytes20[] calldata pubkeyHashes,
        uint32 maxCommittedGasLimit,
        address authorizedOperator
    ) public {
        if (!parameters.ALLOW_UNSAFE_REGISTRATION()) {
            revert UnsafeRegistrationNotAllowed();
        }

        _batchRegisterValidators(pubkeyHashes, authorizedOperator, maxCommittedGasLimit);
    }

    // ========= UPDATE FUNCTIONS =========

    /// @notice Update the maximum gas limit that a validator can commit for preconfirmations
    /// @dev Only the `controller` of the validator can update this value.
    /// @param pubkeyHash The hash of the BLS public key of the validator
    /// @param maxCommittedGasLimit The new maximum gas limit
    function updateMaxCommittedGasLimit(bytes20 pubkeyHash, uint32 maxCommittedGasLimit) public {
        uint32 sequenceNumber = validatorPubkeyHashToSequenceNumber[pubkeyHash];
        _Validator storage _val = VALIDATORS[sequenceNumber];

        if (_val.pubkeyHash == bytes20(0)) {
            revert ValidatorDoesNotExist();
        }

        address controller = controllerIndexToAddress[_val.controllerIndex];
        if (msg.sender != controller) {
            revert UnauthorizedCaller();
        }

        _val.maxCommittedGasLimit = maxCommittedGasLimit;
    }

    // ========= HELPERS =========

    function _registerValidator(bytes20 pubkeyHash, address authorizedOperator, uint32 maxCommittedGasLimit) internal {
        if (authorizedOperator == address(0)) {
            revert InvalidAuthorizedOperator();
        }
        if (pubkeyHash == bytes20(0)) {
            revert InvalidPubkey();
        }
        if (validatorPubkeyHashToSequenceNumber[pubkeyHash] != 0) {
            revert ValidatorAlreadyExists();
        }

        VALIDATORS[nextValidatorSequenceNumber] = _Validator({
            pubkeyHash: pubkeyHash,
            maxCommittedGasLimit: maxCommittedGasLimit,
            authorizedOperatorIndex: _getOrCreateAuthorizedOperatorIndex(authorizedOperator),
            controllerIndex: _getOrCreateControllerIndex(msg.sender)
        });
        emit ValidatorRegistered(pubkeyHash, nextValidatorSequenceNumber);

        validatorPubkeyHashToSequenceNumber[pubkeyHash] = nextValidatorSequenceNumber;
        nextValidatorSequenceNumber += 1;
    }

    function _batchRegisterValidators(
        bytes20[] memory pubkeyHashes,
        address authorizedOperator,
        uint32 maxCommittedGasLimit
    ) internal {
        if (authorizedOperator == address(0)) {
            revert InvalidAuthorizedOperator();
        }

        uint32 authorizedOperatorIndex = _getOrCreateAuthorizedOperatorIndex(authorizedOperator);
        uint32 controllerIndex = _getOrCreateControllerIndex(msg.sender);
        uint256 pubkeysLength = pubkeyHashes.length;

        for (uint32 i; i < pubkeysLength; i++) {
            bytes20 pubkeyHash = pubkeyHashes[i];
            uint32 sequenceNumber = nextValidatorSequenceNumber + i;

            if (pubkeyHash == bytes20(0)) {
                revert InvalidPubkey();
            }
            if (validatorPubkeyHashToSequenceNumber[pubkeyHash] != 0) {
                revert ValidatorAlreadyExists();
            }

            VALIDATORS[sequenceNumber] = _Validator({
                pubkeyHash: pubkeyHash,
                maxCommittedGasLimit: maxCommittedGasLimit,
                authorizedOperatorIndex: authorizedOperatorIndex,
                controllerIndex: controllerIndex
            });
            emit ValidatorRegistered(pubkeyHash, sequenceNumber);

            validatorPubkeyHashToSequenceNumber[pubkeyHash] = sequenceNumber;
        }

        nextValidatorSequenceNumber += uint32(pubkeysLength);
    }

    /// @notice Internal helper to get the index of a new or existing operator by its address.
    /// @param authorizedOperator Address of the operator
    /// @return Index of the operator
    function _getOrCreateAuthorizedOperatorIndex(
        address authorizedOperator
    ) internal returns (uint32) {
        uint32 authorizedOperatorIndex = authorizedOperatorToIndex[authorizedOperator];
        if (authorizedOperatorIndex == 0) {
            authorizedOperatorIndex = nextAuthorizedOperatorIndex;
            authorizedOperatorToIndex[authorizedOperator] = authorizedOperatorIndex;
            authorizedOperatorIndexToAddress[authorizedOperatorIndex] = authorizedOperator;
            nextAuthorizedOperatorIndex += 1;
        }

        return authorizedOperatorIndex;
    }

    /// @notice Internal helper to get the index of a new or existing controller by its address.
    /// @param controller Address of the controller
    /// @return Index of the controller
    function _getOrCreateControllerIndex(
        address controller
    ) internal returns (uint32) {
        uint32 controllerIndex = controllerAddressToIndex[controller];
        if (controllerIndex == 0) {
            controllerIndex = nextControllerIndex;
            controllerAddressToIndex[controller] = controllerIndex;
            controllerIndexToAddress[controllerIndex] = controller;
            nextControllerIndex += 1;
        }

        return controllerIndex;
    }

    /// @notice Internal helper to get the ValidatorInfo struct from a _Validator struct
    /// @param _val Validator struct
    /// @return ValidatorInfo struct
    function _getValidatorInfo(_Validator memory _val) internal view returns (ValidatorInfo memory) {
        return ValidatorInfo({
            pubkeyHash: _val.pubkeyHash,
            maxCommittedGasLimit: _val.maxCommittedGasLimit,
            authorizedOperator: authorizedOperatorIndexToAddress[_val.authorizedOperatorIndex],
            controller: controllerIndexToAddress[_val.controllerIndex]
        });
    }

    /// @notice Compute the hash of a BLS public key
    /// @param pubkey Decompressed BLS public key
    /// @return Hash of the public key in compressed form
    function hashPubkey(
        BLS12381.G1Point memory pubkey
    ) public pure returns (bytes20) {
        uint256[2] memory compressedPubKey = pubkey.compress();
        bytes32 fullHash = keccak256(abi.encodePacked(compressedPubKey));
        // take the leftmost 20 bytes of the keccak256 hash
        return bytes20(uint160(uint256(fullHash)));
    }
}
