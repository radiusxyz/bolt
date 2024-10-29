// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IBoltValidatorsV2} from "../../../src/interfaces/IBoltValidatorsV2.sol";
import {BLS12381} from "../../../src/lib/bls/BLS12381.sol";

import {Script, console} from "forge-std/Script.sol";

/// @notice Script to register Ethereum validators to Bolt
/// @dev this script reads from the config file in /config/holesky/register_validators.json
contract RegisterValidators is Script {
    using BLS12381 for BLS12381.G1Point;

    struct RegisterValidatorsConfig {
        uint32 maxCommittedGasLimit;
        address authorizedOperator;
        // Note: for Unsafe registration (aka without BLS verification precompile)
        // we use compressed pubkey hashes on-chain instead of decompressed points.
        // BLS12381.G1Point[] pubkeys;
        bytes20[] pubkeys;
    }

    function run() public {
        address controller = msg.sender;

        console.log("Registering validators to Bolt");
        console.log("Controller address: ", controller);

        IBoltValidatorsV2 validators = _readValidators();
        RegisterValidatorsConfig memory config = _parseConfig();

        vm.startBroadcast(controller);
        validators.batchRegisterValidatorsUnsafe(config.pubkeys, config.maxCommittedGasLimit, config.authorizedOperator);
        vm.stopBroadcast();

        console.log("Validators registered successfully");
    }

    function _readValidators() public view returns (IBoltValidatorsV2) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return IBoltValidatorsV2(vm.parseJsonAddress(json, ".bolt.validators"));
    }

    function _parseConfig() public view returns (RegisterValidatorsConfig memory config) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/validators.json");
        string memory json = vm.readFile(path);

        config.authorizedOperator = vm.parseJsonAddress(json, ".authorizedOperator");
        config.maxCommittedGasLimit = uint32(vm.parseJsonUint(json, ".maxCommittedGasLimit"));
        console.log("Max committed gas limit:", config.maxCommittedGasLimit);

        string[] memory pubkeysRaw = vm.parseJsonStringArray(json, ".pubkeys");

        // NOTE: for Unsafe registration (aka without BLS verification precompile)
        // we use compressed pubkey hashes on-chain instead of decompressed points.
        bytes20[] memory pubkeys = new bytes20[](pubkeysRaw.length);
        for (uint256 i = 0; i < pubkeysRaw.length; i++) {
            bytes memory pubkeyBytes = vm.parseBytes(pubkeysRaw[i]);
            require(pubkeyBytes.length == 48, "Invalid pubkey length");

            // compute the pubkey hash:
            // 1. create a 64 byte buffer
            // 2. copy the pubkey bytes to the rightmost 48 bytes of the buffer
            // 3. hash the buffer
            // 4. take the 20 leftmost bytes of the hash as the pubkey hash
            bytes memory buffer = new bytes(64);
            for (uint256 j = 0; j < 48; j++) {
                buffer[j + 16] = pubkeyBytes[j];
            }
            bytes20 pubkeyHash = bytes20(keccak256(buffer));

            pubkeys[i] = pubkeyHash;
            console.log("Registering pubkey hash:", vm.toString(abi.encodePacked(pubkeyHash)));
        }

        // BLS12381.G1Point[] memory pubkeys = new BLS12381.G1Point[](pubkeysRaw.length);
        // for (uint256 i = 0; i < pubkeysRaw.length; i++) {
        //     string memory pubkey = pubkeysRaw[i];

        //     string[] memory convertCmd = new string[](2);
        //     convertCmd[0] = "./script/pubkey_to_g1_wrapper.sh";
        //     convertCmd[1] = pubkey;

        //     bytes memory output = vm.ffi(convertCmd);
        //     string memory outputStr = string(output);
        //     string[] memory array = vm.split(outputStr, ",");

        //     uint256[2] memory x = _bytesToParts(vm.parseBytes(array[0]));
        //     uint256[2] memory y = _bytesToParts(vm.parseBytes(array[1]));

        //     pubkeys[i] = BLS12381.G1Point(x, y);

        //     console.log("Registering pubkey:", vm.toString(abi.encodePacked(pubkeys[i].compress())));
        // }

        config.pubkeys = pubkeys;
    }

    function _bytesToParts(
        bytes memory data
    ) public pure returns (uint256[2] memory out) {
        require(data.length == 48, "Invalid data length");

        uint256 value1;
        uint256 value2;

        // Load the first 32 bytes into value1
        assembly {
            value1 := mload(add(data, 32))
        }
        value1 = value1 >> 128; // Clear unwanted upper bits

        // Load the next 16 bytes into value2
        assembly {
            value2 := mload(add(data, 48))
        }
        // value2 = value2 >> 128;

        out[0] = value1;
        out[1] = value2;
    }
}
