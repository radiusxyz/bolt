// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {IAVSDirectory} from "@eigenlayer/src/contracts/interfaces/IAVSDirectory.sol";
import {IDelegationManager} from "@eigenlayer/src/contracts/interfaces/IDelegationManager.sol";
import {IStrategyManager} from "@eigenlayer/src/contracts/interfaces/IStrategyManager.sol";
import {IStrategy, IERC20} from "@eigenlayer/src/contracts/interfaces/IStrategy.sol";
import {ISignatureUtils} from "@eigenlayer/src/contracts/interfaces/ISignatureUtils.sol";

import {BoltEigenLayerMiddlewareV2} from "../../../src/contracts/BoltEigenLayerMiddlewareV2.sol";
import {IBoltMiddlewareV1} from "../../../src/interfaces/IBoltMiddlewareV1.sol";
import {IBoltManagerV2} from "../../../src/interfaces/IBoltManagerV2.sol";

contract RegisterEigenLayerOperator is Script {
    struct OperatorConfig {
        string rpc;
        bytes32 salt;
        uint256 expiry;
    }

    function S01_depositIntoStrategy() public {
        uint256 operatorSk = vm.envUint("OPERATOR_SK");

        IStrategyManager strategyManager = _readStrategyManager();

        string memory json = vm.readFile("config/holesky/operators/eigenlayer/depositIntoStrategy.json");

        IStrategy strategy = IStrategy(vm.parseJsonAddress(json, ".strategy"));
        IERC20 token = IERC20(vm.parseJsonAddress(json, ".token"));
        uint256 amount = vm.parseJsonUint(json, ".amount") * 1 ether;

        vm.startBroadcast(operatorSk);
        // Allowance must be set before depositing
        token.approve(address(strategyManager), amount);
        strategyManager.depositIntoStrategy(strategy, token, amount);
        console.log("Successfully run StrategyManager.depositIntoStrategy");
        vm.stopBroadcast();
    }

    function S02_registerIntoBoltAVS() public {
        uint256 operatorSk = vm.envUint("OPERATOR_SK");
        address operator = vm.addr(operatorSk);

        BoltEigenLayerMiddlewareV2 middleware = _readMiddleware();
        IAVSDirectory avsDirectory = _readAvsDirectory();
        OperatorConfig memory config = _readConfig("config/holesky/operators/eigenlayer/registerIntoBoltAVS.json");

        console.log("Registering EigenLayer operator");
        console.log("Operator address:", operator);
        console.log("Operator RPC:", config.rpc);

        bytes32 digest = avsDirectory.calculateOperatorAVSRegistrationDigestHash({
            operator: operator,
            avs: address(middleware),
            salt: config.salt,
            expiry: config.expiry
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorSk, digest);
        bytes memory rawSignature = abi.encodePacked(r, s, v);

        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature =
            ISignatureUtils.SignatureWithSaltAndExpiry(rawSignature, config.salt, config.expiry);

        vm.startBroadcast(operatorSk);

        middleware.registerOperator(config.rpc, operatorSignature);
        console.log("Successfully registered EigenLayer operator");

        vm.stopBroadcast();
    }

    function S03_checkOperatorRegistration() public view {
        address operatorAddress = vm.envAddress("OPERATOR_ADDRESS");
        console.log("Checking operator registration for address", operatorAddress);

        IBoltManagerV2 boltManager = _readBoltManager();
        bool isRegistered = boltManager.isOperator(operatorAddress);
        console.log("Operator is registered:", isRegistered);
        require(isRegistered, "Operator is not registered");

        BoltEigenLayerMiddlewareV1 middleware = _readMiddleware();
        (address[] memory tokens, uint256[] memory amounts) = middleware.getOperatorCollaterals(operatorAddress);

        for (uint256 i; i < tokens.length; ++i) {
            if (amounts[i] > 0) {
                console.log("Collateral found:", tokens[i], "- amount:", amounts[i]);
            }
        }
    }

    function _readMiddleware() public view returns (BoltEigenLayerMiddlewareV2) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return BoltEigenLayerMiddlewareV2(vm.parseJsonAddress(json, ".eigenLayer.middleware"));
    }

    function _readAvsDirectory() public view returns (IAVSDirectory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return IAVSDirectory(vm.parseJsonAddress(json, ".eigenLayer.avsDirectory"));
    }

    function _readDelegationManager() public view returns (IDelegationManager) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return IDelegationManager(vm.parseJsonAddress(json, ".eigenLayer.delegationManager"));
    }

    function _readStrategyManager() public view returns (IStrategyManager) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);
        return IStrategyManager(vm.parseJsonAddress(json, ".eigenLayer.strategyManager"));
    }

    function _readBoltManager() public view returns (IBoltManagerV2) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);
        return IBoltManagerV2(vm.parseJsonAddress(json, ".bolt.manager"));
    }

    function _readConfig(
        string memory path
    ) public view returns (OperatorConfig memory) {
        string memory json = vm.readFile(path);

        bytes32 salt = bytes32(0);
        uint256 expiry = UINT256_MAX;

        try vm.parseJsonBytes32(json, ".salt") returns (bytes32 val) {
            salt = val;
        } catch {
            console.log("No salt found in config, using 0");
        }

        try vm.parseJsonUint(json, ".expiry") returns (uint256 val) {
            expiry = val;
        } catch {
            console.log("No expiry found in config, using UINT256_MAX");
        }

        return OperatorConfig({rpc: vm.parseJsonString(json, ".rpc"), salt: salt, expiry: expiry});
    }
}
