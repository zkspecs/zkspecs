---

slug: CS-03
title: CS-03/EXCUBIAE
name: Excubiae Smart Contract Framework
status: draft
category: Standards Track
editor: Giacomo Corrias (0xjei) <0xjei@pse.dev>
contributors: 
- ...
- tags:
   - smart contract
   - gatekeeper
   - framework
   - composable
   - policy
   - checker

---

# Change Process

This document is governed by the [1/COSS](../1) (COSS).

# Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

# Abstract
Excubiae is a composable framework for implementing custom, attribute-based access control policies on EVM-compatible networks. At its core, it separates the concerns of **policy** definition (*what rules to enforce*) from policy **checking** (*how to validate those rules*), enabling flexible and reusable access control patterns. The framework's mission is to enable policy enforcement through three key components: **Policies** that define access rules, **Checkers** that validate evidence, and *enforcement* mechanisms that manage the validation flow. Built on values of modularity and reusability, Excubiae provides protocol developers with building blocks to create robust Attribute-Based Access Control (ABAC) systems. In fact, the name "[Excubiae](https://www.nihilscio.it/Manuali/Lingua%20latina/Verbi/Coniugazione_latino.aspx?verbo=excubia&lang=IT_#:~:text=1&text=excubia%20%3D%20sentinella...%20guardia,%2C%20excubia%20%2D%20Sostantivo%201%20decl.)" comes from the ancient Roman guards who kept watch and enforced access control - an apt metaphor for a system designed to protect smart contract access through configurable gatekeepers.

# Motivation
In the evolving blockchain ecosystem, protocols continuously generate new forms of **verifiable evidence** and **proofs** (either backed by cryptography or not). Current access control mechanisms in smart contracts are often rigid, tightly coupled, and lack interoperability, making them unsuitable for interconnection and communication. While these protocols excel at producing such evidence, integrating them into access control systems outside their standard ways of doing it (e.g., APIs / apps / libs / modules) remains challenging. Excubiae aims to bridge this gap by providing a universal framework for composing and enforcing access control policies upon verifiable attributes satisfaction (criterias), expanding and making interoperable forms of on-chain evidence, serving as a foundational layer for ABAC across the ecosystem. In fact, the framework serves multiple audiences: protocol developers integrating access control into their systems, as smart contract engineers implementing custom validation logic for access control on-chain.

# Specification

## System Requirements
The implementations MUST provide:

### Smart Contracts

#### 1. Checker
Checker contracts validate evidence against predefined rules ("verifiable attributes"). Base implementations MUST:

- Provide a stateless validation mechanism through the `check()` method.
- Support encoded evidence via `bytes` parameters.
- Return `boolean` validation results.
- Be reusable across multiple policies.

Advanced implementations MUST:

- Provide a stateless validation mechanism through the `check()` method, taking a supplementary parameter specifying the type of check among the following:
   - **PRE**: Initial validation before main enforcement.
   - **MAIN**: Core validation (as for base implementation).
   - **POST**: Final validation after main enforcement.

#### 2. Policy
Policy contracts define and enforce Checker rules on evidence provided by subjects. Base implementations MUST:

- Define a clear target address representing the protected resource.
- Track enforcement state for subjects.
- Delegate validation to a designated Checker.
- Emit events on successful enforcement.
- Prevent unauthorized access through well-defined error conditions.

Advanced implementations MUST:

- Delegate validation to a designated Checker, taking a supplementary parameter specifying the type of check among the following:
   - **PRE**: Initial validation before main enforcement (can be skipped).
   - **MAIN**: Core validation (as for base implementation).
   - **POST**: Final validation after main enforcement (can be skipped).

#### 3. Factory
Factory contracts enable efficient deployment of Policies and Checkers. Implementations MUST:

- Support the [minimal proxy pattern with immutable args](https://github.com/Vectorized/solady/blob/main/src/utils/LibClone.sol).
- Ensure proper initialization of cloned contracts.
- Enable customizable deployment parameters.

---
## Glossary
This section defines key terms used throughout this specification to ensure clarity and consistency.

- ABAC (Attribute-Based Access Control): A security model that grants access based on verifiable attributes rather than predefined roles.
- RBAC (Role-Based Access Control): A security model that grants access based on predefined and assigned roles.
- Attestation: A verifiable claim or credential issued by a trusted party, proving a subject meets certain conditions.
- Checker: A smart contract responsible for validating evidence submitted by a subject.
- Evidence: Cryptographic proof, attestation, or data submitted by a subject to prove eligibility for access.
- EVM (Ethereum Virtual Machine): The runtime environment for executing smart contracts on Ethereum-compatible networks.
- Nullifier: A mechanism to prevent replay attacks by ensuring each proof or credential is used only once.
- Policy: A smart contract defining access control rules and delegating validation to checkers.
- Proxy Pattern: A design pattern that allows upgradeability of smart contracts by separating storage from logic (e.g., EIP-2535 Diamond Standard).
- Selective Disclosure: A privacy-preserving mechanism that allows users to reveal only necessary parts of their identity or credentials.
- Subject: The entity (e.g., user, contract, or external account) requesting access to a protected resource.
- Target: The entity, contract, or resource for which an access control policy is enforced.
- Verifiable Attributes: Data points that can be independently verified, such as on-chain credentials, cryptographic signatures, or attestations.

## Preliminaries

### Access Control Mode
Excubiae implements an Attribute-Based Access Control (ABAC) model where access decisions are based on attributes associated with the subject. This differs from Role-Based Access Control (RBAC) by allowing more flexible, fine-grained permissions based on arbitrary verifiable evidence rather than predefined roles.

### Evidence Structure
Excubiae supports a flexible evidence format that enables diverse verification methods. Evidence refers to cryptographic proofs, attestations, or data that a subject provides to gain access to a protected resource. All evidence is encoded as `bytes` for future compatibility, composability, and protocol-agnostic validation. Evidence MAY take the following forms:

#### 1. Basic Encoded Evidence
Simple proofs such as token ownership or balance-based access.

```solidity
abi.encodePacked(tokenAddress, tokenId)
```
Example:
```solidity
bytes memory evidence = abi.encodePacked(0x1234..., 42);
```

#### 2. Hashed Commitments
Evidence can be **hashed off-chain** and submitted on-chain to preserve privacy and reduce gas costs.

```solidity
keccak256(abi.encodePacked(secretValue, salt))
```
Example:
```solidity
bytes32 evidenceHash = keccak256(abi.encodePacked(0xdeadbeef, 0xabc123));
```

#### 3. Zero-Knowledge Proofs (ZKPs)
For privacy-preserving authentication, Excubiae supports on-chain verifiable proofs (e.g., ZK-SNARKs), where subjects prove statements without revealing / selectively disclosing underlying information.

Example:
```solidity
struct ZKProof {
    bytes32 a;
    bytes32 b;
    bytes32 c;
    uint256 publicSignals;
}
```
Usage:
```solidity
ZKProof memory zkEvidence = ZKProof(a, b, c, publicSignals);
bytes memory encodedProof = abi.encode(zkEvidence);
```

#### 4. Attestation-Based Evidence
Verifiable credentials issued by a trusted third party, such as decentralized identifiers (DIDs) or attestations.

Example:
```solidity
struct Attestation {
    address issuer;
    address subject;
    bytes32 claimHash;
    bytes signature;
}
```
Encoding:
```solidity
bytes memory attestationData = abi.encode(Attestation(issuer, subject, claimHash, sig));
```

#### 5. Merkle Proof-Based Access
When a subject belongs to a Merkle tree-based access group, a Merkle proof can be submitted to verify inclusion.

Example:
```solidity
struct MerkleProof {
    bytes32[] proof;
    bytes32 root;
    bytes32 leaf;
}
```
Usage:
```solidity
bytes memory merkleEvidence = abi.encode(MerkleProof(proof, root, leaf));
```

### Standard Encoding and Decoding
By maintaining a standardized encoding scheme, Excubiae ensures that Policies and Checkers can interpret diverse types of evidence without tightly coupling access logic to a specific authentication method. All evidence MUST be encoded using `abi.encode()` to ensure compatibility across different implementations. Policies and Checkers MUST decode evidence as needed:

```solidity
// example.
function validateEvidence(bytes calldata evidence) external {
    (address tokenAddress, uint256 tokenId) = abi.decode(evidence, (address, uint256));
}
```

### Private Evidence
The framework is designed to operate entirely on-chain, with all validation and enforcement occurring within the EVM environment. This ensures transparency and auditability. Privacy is tightly coupled with the evidence used: for example, a zero-knowledge proof brings privacy preserving verification for the prover (no disclosure of secrets) while passing a token identifier as evidence has no privacy at all.

---

## Framework Architecture

```
┌─────────────────┐              ┌──────────────────┐
│  PolicyFactory  │              │  CheckerFactory  │
└─────────────────┘              └──────────────────┘
        │                                 │
        │ deploys                         | deploys
        | <clone>                         │ <clone>
        │                                 │
        ▼                                 ▼
 ┌──────────────┐     enforces     ┌──────────────┐
 │   Policy     │ ───────────────> │   Checker    │
 └──────────────┘                  └──────────────┘
       │                                 │
       │ protects                        │ checks
       │                                 │
       ▼                                 ▼
┌──────────────┐                  ┌──────────────┐
│   Target     │                  │   Subject    │
└──────────────┘                  └──────────────┘
```

### Flow
The system MUST implement the following flow when a subject attempts to access a protected target. Note that the following steps are generic and assumes that Checker and Policy clones have been successfully deployed and initialized from respective Factory contracts.

1. Subject provides evidence to a policy.
2. Policy delegates validation to its checker.
3. Checker verifies the evidence.
4. Policy enforces the checker's decision & keeps track of the subject.

#### 1. Checker
A Checker in Excubiae is responsible for validating access conditions. Think of it as the rulebook that defines what constitutes valid access - it receives evidence and determines whether it meets the specified criteria. This contract MUST remain deliberately stateless, focusing solely on validation logic. This design allows checkers to be shared across different policies and enables clear, auditable validation rules. The framework offers two checker variants: BaseChecker and AdvancedChecker.

The Checker MUST be a clonable contract and MUST provide the following internal methods:
- `_initialize()`: Method to initialize the clone. 
   - Must be overridden by derived contracts to implement custom initialization logic.
   - Must Revert if the clone has already been initialized.
- `_getAppendedBytes()`: Method to retrieve appended arguments from the clone.
   - MUST use the Minimal Proxy library utility to extract the arguments specified at deploy time.
   - MUST return the appended bytes extracted from the clone.

The BaseChecker MUST provide a stateless validation mechanism through the `check()` method which takes:
- `subject: address` - An address (EOA or contract) attempting to access a protected resource.
- `evidence: bytes calldata` - Encoded data provided by a subject to prove they satisfy access criteria.

The AdvancedChecker MUST provide a stateless validation mechanism through the `check()` method which takes:
- `subject: address` - An address (EOA or contract) attempting to access a protected resource.
- `evidence: bytes calldata` - Encoded data provided by a subject to prove they satisfy access criteria.
- `checkType: Check` - The phase of validation to execute (PRE, MAIN, POST).

#### 2. Policy
A Policy acts as a gatekeeper, controlling access to protected resources through well-defined enforcement mechanisms. Think of it as a security checkpoint - it doesn't determine the rules itself, but it ensures they are properly enforced.

The Policy MUST be a ownable, clonable contract and MUST provide the following internal methods:
- `_initialize()`: Method to initialize the clone. 
   - Must be overridden by derived contracts to implement custom initialization logic.
   - Must Revert if the clone has already been initialized.
   - Must transfer the ownership to the sender (`msg.sender`).
- `_getAppendedBytes()`: Method to retrieve appended arguments from the clone.
   - MUST use the Minimal Proxy library utility to extract the arguments specified at deploy time.
   - MUST return the appended bytes extracted from the clone.
- `setTarget(_target)`: Method to set the contract address to be protected by the policy.
   - MUST only be called once by the owner.
   - MUST revert when given `_target` is a zero address.
   - MUST revert when has been already set once.
   - SHOULD emit an event `TargetSet(_target)`.

The BasePolicy MUST provide 
- an enforcement mechanism for the provided Checker contract through the `enforce()` method which takes:
   - `subject: address` - An address (EOA or contract) attempting to access a protected resource.
   - `evidence: bytes calldata` - Encoded data provided by a subject to prove they satisfy access criteria.
   - MUST revert when the check is unsuccessful (ie., evaluate to `false`).
   - SHOULD emit an event `Enforced(subject, target, evidence)`.
- override the `_initialize()` method:
   - MUST decode the sender address specified at deploy time.
   - MUST decode the BaseChecker address specified at deploy time.
   - MUST transfer the ownership to the sender address.

The AdvancedPolicy MUST provide 
- an enforcement mechanism for the provided Checker contract through the `enforce()` method which takes:
   - `subject: address` - An address (EOA or contract) attempting to access a protected resource.
   - `evidence: bytes calldata` - Encoded data provided by a subject to prove they satisfy access criteria.
   - `checkType: Check` - The phase of validation to execute (PRE, MAIN, POST).
   - SHOULD skip PRE check based on `skipPre` boolean flag configuration specified at deploy time.
   - SHOULD skip POST check based on `skipPost` boolean flag configuration specified at deploy time.
   - MUST revert when the check is unsuccessful (ie., evaluate to `false`).
   - SHOULD emit an event `Enforced(subject, target, evidence, checkType)`.
- override the `_initialize()` method:
   - MUST decode the sender address specified at deploy time.
   - MUST decode the AdvancedChecker address specified at deploy time.
   - MUST decode the skipPre boolean specified at deploy time.
   - MUST decode the skipPost boolean specified at deploy time.
   - MUST transfer the ownership to the sender address.

#### 3. Factory
Factory contracts enable efficient deployment of Policies and Checkers. Each Factory contract MUST implement:
- `IMPLEMENTATION: address` - A public state variable containing the address of the implementation contract used for cloning. This address is immutable and defines the logic contract for all clones deployed by the factory.
- `_deploy(bytes memory data): address clone` - A method to deploy a new clone contract.
   - MUST be a minimal proxy contract with appended initialization data using the reference proxy library (e.g., [Solady's LibClone](https://github.com/Vectorized/solady/blob/main/src/utils/LibClone.sol))
   - MUST emit a `CloneDeployed(address)` event upon successful deployment.

## Security Considerations
Excubiae is a framework for defining and enforcing access control policies, but its security ultimately depends on the correctness and robustness of the implemented policies and checkers. The framework itself does not guarantee security—it provides a modular structure to enforce rules as defined by the developer. Implementers MUST carefully design their policies and checkers to avoid security risks such as replay attacks, insufficient validation, or incorrect assumptions about external contracts. Secure access control is achieved by selecting strong cryptographic verification methods, minimizing trust assumptions, and thoroughly testing validation mechanisms. The following is the complete list of things that what MUST be addressed:

### Prevention of Double-Enforcement Attacks
Double-enforcement attacks occur when a subject attempts to leverage the same validation evidence multiple times or across different contexts. To prevent these attacks:
- Track unique identifiers for evidence or validation attempts
   - SHOULD implement mappings that mark evidence as "spent" after first use
   - SHOULD consider mechanisms for cross-policy "nullifier" sharing when appropriate
   - CAN implement time-based expiration for enforcement status when appropriate
   - CAN provide mechanisms for authorized revocation of enforcement
- For advanced use cases, you can implement more complex mappings and / or commitment schemes that prevent evidence reuse.
   - MUST track separate state for each validation phase.

### Secure Proxy Initialization
The minimal proxy pattern with immutable args introduces specific security considerations:
- Ensure initialization is performed in the same transaction as deployment
   - MUST implement secure ownership transfer during initialization
- Prevent front-running attacks during deployment 
- Verify that critical parameters cannot be modified after initialization
   - Restrict deployment capabilities to authorized addresses

### Clear Separation Between Validation and State Management
Maintaining separation of concerns is critical for security:
- Ensure Checkers remain purely stateless for validation
- Avoid side effects or state changes in Checker contracts
- Implement view functions for all validation logic
- Restrict all state changes to Policy contracts
- Clearly document state transitions and invariants
- Implement checks-effects-interactions pattern in Policy operations

### Additional Considerations
Implementations SHOULD also consider:

1. **Gas Optimization**
Efficient gas usage is a key consideration when implementing policies and checkers. Implementers SHOULD:
- Balance security with gas efficiency by minimizing redundant on-chain computations.
- Analyze gas costs for various validation scenarios to ensure feasibility for real-world use cases.
- Document gas expectations for implementers to provide clarity on cost implications.

2. **Upgradeability Patterns**
Policies MAY be upgradeable by utilizing proxy patterns (e.g., [EIP-2535 Diamond Standard](https://eips.ethereum.org/EIPS/eip-2535)) or by allowing governance mechanisms to deploy updated versions. 
- If implementing upgradeability, document security implications to avoid unforeseen risks.
- Consider using transparent proxy patterns where applicable, ensuring compatibility with governance structures.
- Implement secure upgrade mechanisms with appropriate time delays to allow for security reviews before changes take effect.

3. **Composability Risks**
Since Excubiae is designed to integrate with multiple protocols, developers SHOULD carefully consider:
- Potential for unexpected interactions with other protocols that may lead to security vulnerabilities.
- Assumptions about external contracts, ensuring predictable behavior when integrating with third-party protocols.
- Implementing fail-safe mechanisms for integration failures, such as timeouts or fallback execution paths.

---

# Implementation Notes
Excubiae is structured as a [TypeScript/Solidity monorepo](https://github.com/privacy-scaling-explorations/excubiae) using [Yarn](https://yarnpkg.com/getting-started) as its package manager. The project is organized into distinct packages and applications:

```
excubiae/
├── packages/
│   ├── contracts/     # Framework implementation
```

The contracts package uniquely combines [Hardhat](https://hardhat.org/) and [Foundry](https://book.getfoundry.sh/) in a way that they can [coexist together](https://hardhat.org/hardhat-runner/docs/advanced/hardhat-and-foundry), offering developers flexibility in their testing approach. This dual-environment setup enables both JavaScript/TypeScript and Solidity-native testing patterns while maintaining complete coverage.

The framework's core implementation resides in `packages/contracts`, structured into distinct layers:
- Core contracts implementing base and advanced validation patterns, minimal proxy pattern with immutable args using [Solady's LibCLone](https://github.com/Vectorized/solady/blob/main/src/utils/LibClone.sol).
- Interface definitions ensuring consistent implementation.
- Test suites demonstrating usage & integration (voting use case for base and advanced scenarios).
- Semaphore extensions which enforces a proof of membership for a Semaphore group with resistance to frontrunning attack vectors.

## Guidelines
The following guidelines MUST be seen as a reference implementation example / guidelines and are based on the [reference implementation codebase](https://github.com/privacy-scaling-explorations/excubiae)

### Writing a Clonable Checker / Policy

When implementing a policy, the first step is defining the criteria for passing validation. These criteria must be verifiable on-chain—such as token ownership, balance thresholds, or protocol-specific credentials.

For example, in a voting system where voters must own a specific NFT to participate, the validation logic resides in a **Checker** contract, while a **Policy** enforces the validation result.

A checker encapsulates validation logic. The [BaseERC721Checker](https://github.com/privacy-scaling-explorations/excubiae/blob/main/packages/contracts/contracts/test/examples/base/BaseERC721Checker.sol) is a clonable contract that verifies NFT ownership. To implement a clonable checker:
- Override `_initialize()`, which is executed only once at deployment time to store immutable arguments in the contract state.
- Implement `_check()`, defining the validation logic.

Once the checker is in place, a **Policy** references it to enforce validation. The [BaseERC721Policy](https://github.com/privacy-scaling-explorations/excubiae/blob/main/packages/contracts/contracts/test/examples/base/BaseERC721Policy.sol) demonstrates how to:
- Extend a base policy contract.
- Provide a unique trait identifier.

```solidity
abstract contract Clone is IClone {
    bool public initialized;

    function initialize() external {
        _initialize();
    }

    function getAppendedBytes() external returns (bytes memory appendedBytes) {
        return _getAppendedBytes();
    }

    function _initialize() internal virtual {
        if (initialized) revert AlreadyInitialized();
        initialized = true;
    }

    function _getAppendedBytes() internal virtual returns (bytes memory appendedBytes) {
        return LibClone.argsOnClone(address(this));
    }
}

abstract contract Policy is Clone, IPolicy, Ownable(msg.sender) {
    address public target;

    modifier onlyTarget() {
        if (msg.sender != target) revert TargetOnly();
        _;
    }

    function _initialize() internal virtual override {
        super._initialize();

        _transferOwnership(msg.sender);
    }

    function setTarget(address _target) external virtual onlyOwner {
        if (_target == address(0)) revert ZeroAddress();
        if (target != address(0)) revert TargetAlreadySet();

        target = _target;
        emit TargetSet(_target);
    }
}

abstract contract BaseChecker is Clone, IBaseChecker {
    function check(address subject, bytes calldata evidence) external view override returns (bool checked) {
        return _check(subject, evidence);
    }

    function _check(address subject, bytes calldata evidence) internal view virtual returns (bool checked) {}
}

abstract contract BasePolicy is Policy, IBasePolicy {
    BaseChecker public BASE_CHECKER;

    function _initialize() internal virtual override {
        super._initialize();

        bytes memory data = _getAppendedBytes();
        (address sender, address baseCheckerAddr) = abi.decode(data, (address, address));

        _transferOwnership(sender);

        BASE_CHECKER = BaseChecker(baseCheckerAddr);
    }

    function enforce(address subject, bytes calldata evidence) external override onlyTarget {
        _enforce(subject, evidence);
    }

    function _enforce(address subject, bytes calldata evidence) internal virtual {
        if (!BASE_CHECKER.check(subject, evidence)) revert UnsuccessfulCheck();

        emit Enforced(subject, target, evidence);
    }
}

contract BaseERC721Checker is BaseChecker {
    IERC721 public nft;

    function _initialize() internal override {
        super._initialize();

        bytes memory data = _getAppendedBytes();

        address nftAddress = abi.decode(data, (address));

        nft = IERC721(nftAddress);
    }

    function _check(address subject, bytes calldata evidence) internal view override returns (bool) {
        super._check(subject, evidence);

        uint256 tokenId = abi.decode(evidence, (uint256));

        return nft.ownerOf(tokenId) == subject;
    }
}

contract BaseERC721Policy is BasePolicy {
    function trait() external pure returns (string memory) {
        return "BaseERC721";
    }
}
```

To deploy clones dynamically, each Checker and Policy implementation requires a corresponding **Factory** contract. Examples include [BaseERC721CheckerFactory](https://github.com/privacy-scaling-explorations/excubiae/blob/main/packages/contracts/contracts/test/examples/base/BaseERC721CheckerFactory.sol) and [BaseERC721PolicyFactory](https://github.com/privacy-scaling-explorations/excubiae/blob/main/packages/contracts/contracts/test/examples/base/BaseERC721PolicyFactory.sol).

Each factory must:
1. Specify the implementation contract in the constructor and pass a new instance to the `Factory()` constructor.
2. Implement a `deploy()` method that:
   - Encodes initialization parameters (**immutable args**).
   - Calls `_deploy(data)`, deploying a clone.
   - Initializes the clone via its `initialize()` method.

```solidity
abstract contract Factory is IFactory {
    address public immutable IMPLEMENTATION;

    constructor(address _implementation) {
        IMPLEMENTATION = _implementation;
    }

    function _deploy(bytes memory data) internal returns (address clone) {
        clone = LibClone.clone(IMPLEMENTATION, data);

        emit CloneDeployed(clone);
    }
}

contract BaseERC721CheckerFactory is Factory {
    constructor() Factory(address(new BaseERC721Checker())) {}

    function deploy(address _nftAddress) public {
        bytes memory data = abi.encode(_nftAddress);

        address clone = super._deploy(data);

        BaseERC721Checker(clone).initialize();
   }
}

contract BaseERC721PolicyFactory is Factory {
    constructor() Factory(address(new BaseERC721Policy())) {}

    function deploy(address _checkerAddr) public {
        bytes memory data = abi.encode(msg.sender, _checkerAddr);

        address clone = super._deploy(data);

        BaseERC721Policy(clone).initialize();
    }
}
```

This approach enables efficient deployments and customization at deploy time. For example, different `_nftAddress` values can be set per clone, allowing multiple NFT collections to use the same validation logic while remaining independent.

### Integrating a Policy
The [BaseVoting](https://github.com/privacy-scaling-explorations/excubiae/blob/main/packages/contracts/contracts/test/examples/base/BaseVoting.sol) contract demonstrates a complete implementation of policy integration. It shows how to:
- Initialize the policy
- Enforce checks before actions
- Track validation state

```solidity
contract BaseVoting {
    event Registered(address voter);
    event Voted(address voter, uint8 option);

    error NotRegistered();
    error AlreadyVoted();
    error InvalidOption();

    BaseERC721Policy public immutable POLICY;
    mapping(address => bool) public registered;
    mapping(address => bool) public hasVoted;

    constructor(BaseERC721Policy _policy) {
        POLICY = _policy;
    }

    function register(uint256 tokenId) external {
        POLICY.enforce(msg.sender, abi.encode(tokenId));

        registered[msg.sender] = true;

        emit Registered(msg.sender);
    }

    function vote(uint8 option) external {
        // Check registration and voting status.
        if (!registered[msg.sender]) revert NotRegistered();
        if (hasVoted[msg.sender]) revert AlreadyVoted();
        if (option >= 2) revert InvalidOption();

        // Record the vote.
        hasVoted[msg.sender] = true;

        emit Voted(msg.sender, option);
    }
}
```

#### Tracking Mechanisms to Prevent Double Enforcement
Each Policy in Excubiae must implement its own tracking mechanism to prevent double enforcement. This ensures that the same proof or validation cannot be reused maliciously. The design of the tracking system may vary depending on the specific requirements of the policy.

Example from [SemaphorePolicy](https://github.com/privacy-scaling-explorations/excubiae/blob/70967948b4025c3f7bbbf833c06cf5944187837d/packages/contracts/contracts/extensions/SemaphorePolicy.sol#L34):

```solidity
contract SemaphorePolicy is BasePolicy {
    mapping(uint256 => bool) public spentNullifiers;

    error AlreadySpentNullifier();

    function trait() external pure returns (string memory) {
        return "Semaphore";
    }

    function _enforce(address subject, bytes calldata evidence) internal override {
        ISemaphore.SemaphoreProof memory proof = abi.decode(evidence, (ISemaphore.SemaphoreProof));
        uint256 _nullifier = proof.nullifier;

        if (spentNullifiers[_nullifier]) revert AlreadySpentNullifier();

        spentNullifiers[_nullifier] = true;

        super._enforce(subject, evidence);
    }
}
```

This pattern ensures that each proof is only used once, maintaining the integrity of the access control system.

---

# Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).