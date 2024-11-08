// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";

import {BoltParametersV1} from "../src/contracts/BoltParametersV1.sol";
import {BoltValidatorsV1} from "../src/contracts/BoltValidatorsV1.sol";
import {IBoltValidatorsV1} from "../src/interfaces/IBoltValidatorsV1.sol";
import {BLS12381} from "../src/lib/bls/BLS12381.sol";
import {BoltConfig} from "../src/lib/BoltConfig.sol";
import {Utils} from "./Utils.sol";

contract BoltValidatorsTest is Test {
    using BLS12381 for BLS12381.G1Point;

    BoltParametersV1 public parameters;
    BoltValidatorsV1 public validators;

    uint128 public constant PRECONF_MAX_GAS_LIMIT = 5_000_000;

    address admin = makeAddr("admin");
    address provider = makeAddr("provider");
    address operator = makeAddr("operator");
    address validator = makeAddr("validator");

    function setUp() public {
        vm.pauseGasMetering();
        BoltConfig.Parameters memory config = new Utils().readParameters();

        parameters = new BoltParametersV1();
        parameters.initialize(
            admin,
            config.epochDuration,
            config.slashingWindow,
            config.maxChallengeDuration,
            config.allowUnsafeRegistration,
            config.challengeBond,
            config.blockhashEvmLookback,
            config.justificationDelay,
            config.eth2GenesisTimestamp,
            config.slotTime,
            config.minimumOperatorStake
        );

        validators = new BoltValidatorsV1();
        validators.initialize(admin, address(parameters));
    }

    function testUnsafeRegistration() public {
        // pubkeys aren't checked, any point will be fine
        BLS12381.G1Point memory pubkey = BLS12381.generatorG1();

        vm.resumeGasMetering();
        vm.prank(validator);
        validators.registerValidatorUnsafe(pubkey, 1_000_000, operator);
        vm.pauseGasMetering();

        BoltValidatorsV1.Validator memory registered = validators.getValidatorByPubkey(pubkey);
        assertEq(registered.exists, true);
        assertEq(registered.maxCommittedGasLimit, 1_000_000);
        assertEq(registered.authorizedOperator, operator);
        assertEq(registered.controller, validator);
    }

    function testUnsafeRegistrationFailsIfAlreadyRegistered() public {
        BLS12381.G1Point memory pubkey = BLS12381.generatorG1();

        vm.prank(validator);
        vm.resumeGasMetering();
        validators.registerValidatorUnsafe(pubkey, PRECONF_MAX_GAS_LIMIT, operator);
        vm.pauseGasMetering();

        vm.prank(validator);
        vm.expectRevert(IBoltValidatorsV1.ValidatorAlreadyExists.selector);
        validators.registerValidatorUnsafe(pubkey, PRECONF_MAX_GAS_LIMIT, operator);
    }

    function testUnsafeRegistrationWhenNotAllowed() public {
        BLS12381.G1Point memory pubkey = BLS12381.generatorG1();

        vm.prank(admin);
        parameters.setAllowUnsafeRegistration(false);

        vm.prank(validator);
        vm.expectRevert(IBoltValidatorsV1.UnsafeRegistrationNotAllowed.selector);
        vm.resumeGasMetering();
        validators.registerValidatorUnsafe(pubkey, PRECONF_MAX_GAS_LIMIT, operator);
        vm.pauseGasMetering();
    }

    function testUnsafeRegistrationInvalidOperator() public {
        BLS12381.G1Point memory pubkey = BLS12381.generatorG1();

        vm.prank(validator);
        vm.resumeGasMetering();
        vm.expectRevert(IBoltValidatorsV1.InvalidAuthorizedOperator.selector);
        validators.registerValidatorUnsafe(pubkey, PRECONF_MAX_GAS_LIMIT, address(0));
        vm.pauseGasMetering();
    }

    function testUnsafeBatchRegistrationGasUsage() public {
        BLS12381.G1Point[] memory pubkeys = _readPubkeysFromFile(290);

        vm.prank(validator);
        vm.resumeGasMetering();
        validators.batchRegisterValidatorsUnsafe(pubkeys, PRECONF_MAX_GAS_LIMIT, operator);
        vm.pauseGasMetering();

        for (uint256 i = 0; i < pubkeys.length; i++) {
            BoltValidatorsV1.Validator memory registered = validators.getValidatorByPubkey(pubkeys[i]);
            assertEq(registered.exists, true);
            assertEq(registered.maxCommittedGasLimit, PRECONF_MAX_GAS_LIMIT);
            assertEq(registered.authorizedOperator, operator);
            assertEq(registered.controller, validator);
        }
    }

    /// @notice Read validator pubkeys from a file and convert them to G1 points
    /// @param amount The number of pubkeys to read (capped to the number of pubkeys in the file)
    function _readPubkeysFromFile(
        uint256 amount
    ) internal returns (BLS12381.G1Point[] memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/test/testdata/validator_pubkeys.json");
        string memory json = vm.readFile(path);

        string[] memory pubkeysRaw = vm.parseJsonStringArray(json, ".pubkeys");

        if (amount > pubkeysRaw.length) {
            revert("Amount exceeds the number of pubkeys in the file");
        }

        BLS12381.G1Point[] memory pubkeys = new BLS12381.G1Point[](amount);

        for (uint256 i = 0; i < amount; i++) {
            string memory pubkey = pubkeysRaw[i];

            string[] memory convertCmd = new string[](2);
            convertCmd[0] = string.concat(root, "/script/pubkey_to_g1_wrapper.sh");
            convertCmd[1] = pubkey;

            bytes memory output = vm.ffi(convertCmd);
            string memory outputStr = string(output);
            string[] memory array = vm.split(outputStr, ",");

            uint256[2] memory x = _bytesToParts(vm.parseBytes(array[0]));
            uint256[2] memory y = _bytesToParts(vm.parseBytes(array[1]));

            pubkeys[i] = BLS12381.G1Point(x, y);
        }

        return pubkeys;
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
