// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

/// @title ValidatorsLib
/// @notice A library for managing a set of validators along with their information
library ValidatorsLib {
    error ValidatorAlreadyExists(bytes20 pubkeyHash);
    error ValidatorDoesNotExist(bytes20 pubkeyHash);

    struct _AddressSet {
        address[] _values;
        // We use index 0 to represent a non-existent value
        mapping(address => uint32) _indexes;
    }

    /// @dev The internal representation of a validator in the set.
    /// This takes only 1 slot in tightly packed storage.
    struct _Validator {
        bytes20 pubkeyHash;
        uint32 maxCommittedGasLimit;
        uint32 controllerIndex;
        uint32 authorizedOperatorIndex;
    }

    struct ValidatorSet {
        _Validator[] _values;
        mapping(bytes20 => uint32) _indexes;
        _AddressSet _controllers;
        _AddressSet _authorizedOperators;
    }

    // ================ VALIDATOR SET LOGIC ================

    function get(ValidatorSet storage self, bytes20 pubkeyHash) internal view returns (_Validator memory) {
        uint32 index = self._indexes[pubkeyHash];
        if (index == 0) {
            revert ValidatorDoesNotExist(pubkeyHash);
        }

        return self._values[index - 1];
    }

    /// @dev DANGER: this function copies all data into memory. This should be used off-chain.
    function getAll(
        ValidatorSet storage self
    ) internal view returns (_Validator[] memory) {
        return self._values;
    }

    function contains(ValidatorSet storage self, bytes20 pubkeyHash) internal view returns (bool) {
        return self._indexes[pubkeyHash] != 0;
    }

    function length(
        ValidatorSet storage self
    ) internal view returns (uint256) {
        return self._values.length;
    }

    function insert(
        ValidatorSet storage self,
        bytes20 pubkeyHash,
        uint32 maxCommittedGasLimit,
        uint32 controllerIndex,
        uint32 authorizedOperatorIndex
    ) internal {
        if (self._indexes[pubkeyHash] != 0) {
            revert ValidatorAlreadyExists(pubkeyHash);
        }

        self._values.push(_Validator(pubkeyHash, maxCommittedGasLimit, controllerIndex, authorizedOperatorIndex));
        self._indexes[pubkeyHash] = uint32(self._values.length);
    }

    function updateMaxCommittedGasLimit(
        ValidatorSet storage self,
        bytes20 pubkeyHash,
        uint32 maxCommittedGasLimit
    ) internal {
        uint32 index = self._indexes[pubkeyHash];
        if (index == 0) {
            revert ValidatorDoesNotExist(pubkeyHash);
        }

        self._values[index - 1].maxCommittedGasLimit = maxCommittedGasLimit;
    }

    function getController(ValidatorSet storage self, bytes20 pubkeyHash) internal view returns (address) {
        return at(self._controllers, get(self, pubkeyHash).controllerIndex);
    }

    function getAuthorizedOperator(ValidatorSet storage self, bytes20 pubkeyHash) internal view returns (address) {
        return at(self._authorizedOperators, get(self, pubkeyHash).authorizedOperatorIndex);
    }

    function getOrInsertController(ValidatorSet storage self, address controller) internal returns (uint32) {
        return getOrInsert(self._controllers, controller);
    }

    function getOrInsertAuthorizedOperator(
        ValidatorSet storage self,
        address authorizedOperator
    ) internal returns (uint32) {
        return getOrInsert(self._authorizedOperators, authorizedOperator);
    }

    // ================ ADDRESS SET HELPERS ================

    function getOrInsert(_AddressSet storage self, address value) internal returns (uint32) {
        uint32 index = self._indexes[value];
        if (index == 0) {
            self._values.push(value);
            self._indexes[value] = uint32(self._values.length);
            return uint32(self._values.length);
        } else {
            return index;
        }
    }

    function at(_AddressSet storage self, uint32 index) internal view returns (address) {
        return self._values[index - 1];
    }
}
