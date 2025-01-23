use alloy::sol;
use serde::Serialize;

// Mainnet Genesis: deprecated
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface BoltValidators {
        #[derive(Debug, Serialize)]
        struct ValidatorInfo {
            bytes20 pubkeyHash;
            uint32 maxCommittedGasLimit;
            address authorizedOperator;
            address controller;
        }

        /// @notice Register a batch of Validators and authorize a Collateral Provider and Operator for them
        /// @dev This function allows anyone to register a list of Validators.
        /// @param pubkeyHashes List of BLS public key hashes for the Validators to be registered
        /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
        /// @param authorizedOperator The address of the authorized operator
        function batchRegisterValidatorsUnsafe(bytes20[] calldata pubkeyHashes, uint32 maxCommittedGasLimit, address authorizedOperator);

        /// @notice Get a validator by its BLS public key hash
        /// @param pubkeyHash BLS public key hash of the validator
        /// @return ValidatorInfo struct
        function getValidatorByPubkeyHash(bytes20 pubkeyHash) public view returns (ValidatorInfo memory);

        #[derive(Debug)]
        error KeyNotFound();
        #[derive(Debug)]
        error InvalidQuery();
        #[derive(Debug)]
        error ValidatorDoesNotExist(bytes20 pubkeyHash);
        #[derive(Debug)]
        error ValidatorAlreadyExists(bytes20 pubkeyHash);
        #[derive(Debug)]
        error InvalidAuthorizedOperator();
    }
}

// Mainnet Genesis: deprecated
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    struct SignatureWithSaltAndExpiry {
        bytes signature;
        bytes32 salt;
        uint256 expiry;
    }

    // === Holesky contracts ===

    #[allow(missing_docs)]
    #[sol(rpc)]
    interface BoltEigenLayerMiddlewareHolesky {
        /// @notice Allow an operator to signal opt-in to Bolt Protocol.
        /// @dev This requires calling the EigenLayer AVS Directory contract to register the operator.
        /// EigenLayer internally contains a mapping from `msg.sender` (our AVS contract) to the operator.
        /// The msg.sender of this call will be the operator address.
        function registerOperator(string calldata rpc, SignatureWithSaltAndExpiry calldata operatorSignature) public;

        /// @notice Deregister an EigenLayer operator from working in Bolt Protocol.
        /// @dev This requires calling the EigenLayer AVS Directory contract to deregister the operator.
        /// EigenLayer internally contains a mapping from `msg.sender` (our AVS contract) to the operator.
        function deregisterOperator() public;

        error AlreadyRegistered();
        error NotOperator();
        error NotRegistered();
        error KeyNotFound(address key);
        error SaltSpent();

        // From IDelegationManager
        /// @dev Thrown when an account is not actively delegated.
        error NotActivelyDelegated();
        /// @dev Thrown when `operator` is not a registered operator.
        error OperatorNotRegistered();
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    interface BoltSymbioticMiddlewareHolesky {
        /// @notice Allow an operator to signal opt-in to Bolt Protocol.
        /// msg.sender must be an operator in the Symbiotic network.
        function registerOperator(string calldata rpc) public;

        /// @notice Deregister a Symbiotic operator from working in Bolt Protocol.
        /// @dev This does NOT deregister the operator from the Symbiotic network.
        function deregisterOperator() public;

        /// @notice Get the collaterals and amounts staked by an operator across the supported strategies.
        ///
        /// @param operator The operator address to get the collaterals and amounts staked for.
        /// @return collaterals The collaterals staked by the operator.
        /// @dev Assumes that the operator is registered and enabled.
        function getOperatorCollaterals(address operator) public view returns (address[] memory, uint256[] memory);

        error AlreadyRegistered();
        error NotOperator();
        error NotRegistered();
        error KeyNotFound();
    }

    // === Mainnet contracts ===

    #[allow(missing_docs)]
    #[sol(rpc)]
    interface BoltEigenLayerMiddlewareMainnet {
        function updateOperatorRpcEndpoint(string calldata rpcEndpoint) public;

        function getOperatorCollaterals(address operator) public view returns (address[] memory, uint256[] memory);

        function getOperatorStake(address operator, address collateral) public view returns (uint256);

        function registerThroughAVSDirectory(
            string memory rpcEndpoint,
            string memory extraData,
            SignatureWithSaltAndExpiry calldata operatorSignature
        ) public;

        function deregisterThroughAVSDirectory() public;

        error InvalidRpc();
        error InvalidSigner();
        error Unauthorized();
        error UnknownOperator();
        error OnlyRestakingMiddlewares();
        error InvalidMiddleware(string reason);
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    interface BoltSymbioticMiddlewareMainnet {
        function updateOperatorRpcEndpoint(string calldata rpcEndpoint) public;

        function getOperatorCollaterals(address operator) public view returns (address[] memory, uint256[] memory);

        function getOperatorStake(address operator, address collateral) public view returns (uint256);

        function registerOperator(string calldata rpcEndpoint, string calldata extraData) public;

        function deregisterOperator() public;

        error NotOperator();
        error OperatorNotOptedIn();
        error OperatorNotRegistered();

        error NotVault();
        error VaultNotInitialized();
        error VaultAlreadyWhitelisted();
        error UnauthorizedVault();
        error NotOperatorSpecificVault();
    }
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface OperatorsRegistryV1 {
        /// @notice Operator struct
        struct Operator {
            address signer;
            string rpcEndpoint;
            address restakingMiddleware;
            string extraData;
        }

        /// @notice Emitted when a new operator is registered
        /// @param signer The address of the operator
        /// @param rpcEndpoint The rpc endpoint of the operator
        /// @param restakingMiddleware The address of the restaking middleware
        event OperatorRegistered(address signer, string rpcEndpoint, address restakingMiddleware, string extraData);

        /// @notice Emitted when an operator is deregistered
        /// @param signer The address of the operator
        /// @param restakingMiddleware The address of the restaking middleware
        event OperatorDeregistered(address signer, address restakingMiddleware);

        /// @notice Emitted when an operator is paused
        /// @param signer The address of the operator
        /// @param restakingMiddleware The address of the restaking middleware
        event OperatorPaused(address signer, address restakingMiddleware);

        /// @notice Emitted when an operator is unpaused
        /// @param signer The address of the operator
        /// @param restakingMiddleware The address of the restaking middleware
        event OperatorUnpaused(address signer, address restakingMiddleware);

        /// @notice Returns the start timestamp of the registry contract
        function START_TIMESTAMP() external view returns (uint48);

        /// @notice Returns the duration of an epoch in seconds
        function EPOCH_DURATION() external view returns (uint48);

        /// @notice Returns the address of the EigenLayer restaking middleware
        function EIGENLAYER_RESTAKING_MIDDLEWARE() external view returns (address);

        /// @notice Returns the address of the Symbiotic restaking middleware
        function SYMBIOTIC_RESTAKING_MIDDLEWARE() external view returns (address);

        /// @notice Register an operator in the registry
        /// @param signer The address of the operator
        /// @param rpcEndpoint The rpc endpoint of the operator
        /// @param extraData Arbitrary data the operator can provide as part of registration
        function registerOperator(address signer, string memory rpcEndpoint, string memory extraData) external;

        /// @notice Deregister an operator from the registry
        /// @param signer The address of the operator
        function deregisterOperator(
            address signer
        ) external;

        /// @notice Update the rpc endpoint of an operator
        /// @param signer The address of the operator
        /// @param rpcEndpoint The new rpc endpoint
        /// @dev Only restaking middleware contracts can call this function
        function updateOperatorRpcEndpoint(address signer, string memory rpcEndpoint) external;

        /// @notice Pause an operator in the registry
        /// @param signer The address of the operator
        function pauseOperator(
            address signer
        ) external;

        /// @notice Unpause an operator in the registry, marking them as "active"
        /// @param signer The address of the operator
        function unpauseOperator(
            address signer
        ) external;

        /// @notice Returns all the operators saved in the registry, including inactive ones.
        /// @return operators The array of operators
        function getAllOperators() external view returns (Operator[] memory);

        /// @notice Returns the active operators in the registry.
        /// @return operators The array of active operators.
        function getActiveOperators() external view returns (Operator[] memory);

        /// @notice Returns true if the given address is an operator in the registry.
        /// @param signer The address of the operator.
        /// @return isOperator True if the address is an operator, false otherwise.
        function isOperator(
            address signer
        ) external view returns (bool);

        /// @notice Returns true if the given operator is registered AND active.
        /// @param signer The address of the operator
        /// @return isActiveOperator True if the operator is active, false otherwise.
        function isActiveOperator(
            address signer
        ) external view returns (bool);

        /// @notice Cleans up any expired operators (i.e. paused + IMMUTABLE_PERIOD has passed).
        function cleanup() external;

        /// @notice Returns the timestamp of when the current epoch started
        function getCurrentEpochStartTimestamp() external view returns (uint48);
    }
}
