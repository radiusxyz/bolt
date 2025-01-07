// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {INetworkRegistry} from "@symbiotic/interfaces/INetworkRegistry.sol";
import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";

/// @notice Helper script to interact with Symbiotic protocol
/// 1. forge script script/holesky/Symbiotic.s.sol --rpc-url $RPC_HOLESKY --private-key $NETWORK_PRIVATE_KEY --broadcast -vvvv --sig "run(string memory arg)" registerNetwork
/// 2. forge script script/holesky/Symbiotic.s.sol --rpc-url $RPC_HOLESKY --private-key $NETWORK_PRIVATE_KEY --broadcast -vvvv --sig "run(string memory arg)" registerMiddleware
/// 3. forge script script/holesky/Symbiotic.s.sol --rpc-url $RPC_HOLESKY --private-key $NETWORK_PRIVATE_KEY --broadcast -vvvv --sig "run(string memory arg)" setMaxNetworkLimit
/// 4. forge script script/holesky/Symbiotic.s.sol --rpc-url $RPC_HOLESKY --private-key $VAULT_PRIVATE_KEY --broadcast -vvvv --sig "run(string memory arg)" setNetworkLimit
/// 5. forge script script/holesky/Symbiotic.s.sol --rpc-url $RPC_HOLESKY --private-key $VAULT_PRIVATE_KEY --broadcast -vvvv --sig "run(string memory arg)" setOperatorNetworkShares
contract SymbioticHelper is Script {
    function run(
        string memory arg
    ) public {
        address admin = msg.sender;
        console.log("Running with message sender:", admin);

        vm.startBroadcast(admin);

        // NOTE: requires msg.sender == networkAdmin
        if (keccak256(abi.encode(arg)) == keccak256(abi.encode("registerNetwork"))) {
            INetworkRegistry networkRegistry = INetworkRegistry(readNetworkRegistry());

            console.log("Registering network with NetworkRegistry (%s)", address(networkRegistry));

            networkRegistry.registerNetwork();

            // NOTE: requires msg.sender == networkAdmin
        } else if (keccak256(abi.encode(arg)) == keccak256(abi.encode("registerMiddleware"))) {
            INetworkMiddlewareService middlewareService = INetworkMiddlewareService(readMiddlewareService());

            address middleware = readMiddleware();

            console.log(
                "Registering network middleware (%s) with MiddlewareService (%s)",
                middleware,
                address(middlewareService)
            );

            middlewareService.setMiddleware(middleware);

            // NOTE: requires msg.sender == networkAdmin
        } else if (keccak256(abi.encode(arg)) == keccak256(abi.encode("setMaxNetworkLimit"))) {
            // NOTE: change this to the subnetworkID you want to set the max network limit for
            uint64 subnetworkId = 0;
            uint256 amount = 1_000_000_000_000_000_000_000; // 1000 ETH, customize as needed

            address[] memory vaults = readVaults();

            console.log("Setting global max network limit for all vaults");
            for (uint256 i = 0; i < vaults.length; i++) {
                address delegator = IVault(vaults[i]).delegator();
                INetworkRestakeDelegator(delegator).setMaxNetworkLimit(subnetworkId, amount);
                console.log("Set max network limit for vault (%s)", vaults[i]);
            }

            console.log("Set max network limit for all vaults");

            // NOTE: requires msg.sender == vaultAdmin
        } else if (keccak256(abi.encode(arg)) == keccak256(abi.encode("setNetworkLimit"))) {
            // NOTE: change this to the subnetwork you want to set the max network limit for
            bytes32 subnetwork = 0xb017002D8024d8c8870A5CECeFCc63887650D2a4000000000000000000000000;
            uint256 amount = 1_000_000_000_000_000_000_000; // 1000 ETH, customize as needed

            address[] memory vaults = readVaults();

            console.log("Setting the vault-specific network limit for each vault");
            for (uint256 i = 0; i < vaults.length; i++) {
                address delegator = IVault(vaults[i]).delegator();
                INetworkRestakeDelegator(delegator).setNetworkLimit(subnetwork, amount);
                console.log("Set vault network limit for vault (%s)", vaults[i]);
            }
            console.log("Set network limit for all vaults");

            // NOTE: requires msg.sender == vaultAdmin
        } else if (keccak256(abi.encode(arg)) == keccak256(abi.encode("setOperatorNetworkShares"))) {
            // NOTE: change this to the subnetwork you want to set the operator network shares for
            bytes32 subnetwork = 0xb017002D8024d8c8870A5CECeFCc63887650D2a4000000000000000000000000;
            address operator = 0x57b6FdEF3A23B81547df68F44e5524b987755c99;
            uint256 amount = 1_000_000_000_000_000_000; // 1 ETH, customize as needed

            address[] memory vaults = readVaults();

            console.log("Minting the operator network shares for all vaults");
            for (uint256 i = 0; i < vaults.length; i++) {
                address delegator = IVault(vaults[i]).delegator();
                INetworkRestakeDelegator(delegator).setOperatorNetworkShares(subnetwork, operator, amount);
                console.log("Set operator network shares for vault (%s)", vaults[i]);
            }

            console.log("Set operator network shares for all vaults");
        }

        vm.stopBroadcast();
    }

    function readNetworkRegistry() public view returns (address) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return vm.parseJsonAddress(json, ".symbiotic.networkRegistry");
    }

    function readMiddlewareService() public view returns (address) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return vm.parseJsonAddress(json, ".symbiotic.networkMiddlewareService");
    }

    function readVaults() public view returns (address[] memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return vm.parseJsonAddressArray(json, ".symbiotic.supportedVaults");
    }

    function readMiddleware() public view returns (address) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return vm.parseJsonAddress(json, ".symbiotic.middleware");
    }
}
