---

slug: CS-03
title: CS-03/EXCUBIAE-V0.3.0
name: ABAC Smart Contract Framework
status: draft
category: Standards Track
editor: Giacomo Corrias <0xjei@pse.dev>
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
Excubiae is a composable framework for implementing custom, attribute-based access control policies on EVM-compatible networks. At its core, it separates the concerns of **policy** definition (*what rules to enforce*) from policy **checking** (*how to validate those rules*), enabling flexible and reusable access control patterns. The framework's mission is to enable policy enforcement through three key components: **Policies** that define access rules, **Checkers** that validate evidence, and *enforcement* mechanisms that manage the validation flow. Built on values of modularity, reusability, and security, Excubiae provides protocol developers with building blocks to create robust attribute-based access control (ABAC) systems. In fact, the name "[Excubiae](https://www.nihilscio.it/Manuali/Lingua%20latina/Verbi/Coniugazione_latino.aspx?verbo=excubia&lang=IT_#:~:text=1&text=excubia%20%3D%20sentinella...%20guardia,%2C%20excubia%20%2D%20Sostantivo%201%20decl.)" comes from the ancient Roman guards who kept watch and enforced access control - an apt metaphor for a system designed to protect smart contract access through configurable policies.

# Motivation

In the evolving blockchain ecosystem, protocols continuously generate new forms of **verifiable evidence** and **proofs** (either backed by cryptography or not). Current access control mechanisms in smart contracts are often rigid, tightly coupled, and lack interoperability, making them unsuitable for interconnection and communication. While these protocols excel at producing such evidence, integrating them into access control systems outside their standard ways of doing it (e.g., APIs / apps / libs / modules) remains challenging. Excubiae aims to bridge this gap by providing a universal framework for composing and enforcing access control policies upon verifiable attributes satisfaction (criterias), expanding and making interoperable forms of on-chain evidence, serving as a foundational layer for ABAC across the ecosystem. In fact, the framework serves multiple audiences: protocol developers integrating access control into their systems, as smart contract engineers implementing custom validation logic for access control on-chain.

# Specification

## System Requirements

The implementations MUST provide:

### Framework


#### 1. Policy
Policies define and enforce access rules based on evidence provided by subjects. Base implementations MUST:
- Define a clear target address representing the protected resource.
- Track enforcement state for subjects.
- Delegate validation to a designated Checker.
- Emit events on successful enforcement.
- Prevent unauthorized access through well-defined error conditions.

#### 2. Checker
Checkers validate evidence against predefined rules. Base implementations MUST:

- Provide a stateless validation mechanism through the `check()` method.
- Support encoded evidence via `bytes` parameters.
- Return `boolean` validation results.
- Be reusable across multiple policies.

#### 3. Factory
Factory contracts enable efficient deployment of Policies and Checkers. Implementations MUST:

- Support the [minimal proxy pattern with immutable args](https://github.com/Vectorized/solady/blob/main/src/utils/LibClone.sol).
- Ensure proper initialization of cloned contracts.
- Enable customizable deployment parameters.

#### 4. Advanced Multi-Phase Validation
Advanced implementations SHOULD support multi-phase validation for evidence check and enforcement:

- **PRE**: Initial validation before main enforcement.
- **MAIN**: Core validation (as for base implementation).
- **POST**: Final validation after main enforcement.




---

slug: CS-03
title: CS-03/EXCUBIAE-V0.3.0
name: ABAC Smart Contract Framework
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
Excubiae is a composable framework for implementing custom, attribute-based access control policies on EVM-compatible networks. At its core, it separates the concerns of **policy** definition (*what rules to enforce*) from policy **checking** (*how to validate those rules*), enabling flexible and reusable access control patterns. The framework's mission is to enable policy enforcement through three key components: **Policies** that define access rules, **Checkers** that validate evidence, and *enforcement* mechanisms that manage the validation flow. Built on values of modularity, reusability, and security, Excubiae provides protocol developers with building blocks to create robust attribute-based access control (ABAC) systems. In fact, the name "[Excubiae](https://www.nihilscio.it/Manuali/Lingua%20latina/Verbi/Coniugazione_latino.aspx?verbo=excubia&lang=IT_#:~:text=1&text=excubia%20%3D%20sentinella...%20guardia,%2C%20excubia%20%2D%20Sostantivo%201%20decl.)" comes from the ancient Roman guards who kept watch and enforced access control - an apt metaphor for a system designed to protect smart contract access through configurable policies.

# Motivation

In the evolving blockchain ecosystem, protocols continuously generate new forms of **verifiable evidence** and **proofs** (either backed by cryptography or not). Current access control mechanisms in smart contracts are often rigid, tightly coupled, and lack interoperability, making them unsuitable for interconnection and communication. While these protocols excel at producing such evidence, integrating them into access control systems outside their standard ways of doing it (e.g., APIs / apps / libs / modules) remains challenging. Excubiae aims to bridge this gap by providing a universal framework for composing and enforcing access control policies upon verifiable attributes satisfaction (criterias), expanding and making interoperable forms of on-chain evidence, serving as a foundational layer for ABAC across the ecosystem. In fact, the framework serves multiple audiences: protocol developers integrating access control into their systems, as smart contract engineers implementing custom validation logic for access control on-chain.

# Specification

## System Requirements

The implementations MUST provide:

### Smart Contracts

#### 1. Checker
Checker contracts validate evidence against predefined rules. Base implementations MUST:

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
Policy contracts define and enforce access rules based on evidence provided by subjects. Base implementations MUST:

- Define a clear target address representing the protected resource.
- Track enforcement state for subjects.
- Delegate validation to a designated Checker.
- Emit events on successful enforcement.
- Prevent unauthorized access through well-defined error conditions.

Advanced implementations MUST:

- Delegate validation to a designated Checker, taking a supplementary parameter specifying the type of check among the following:
   - **PRE**: Initial validation before main enforcement.
   - **MAIN**: Core validation (as for base implementation).
   - **POST**: Final validation after main enforcement.

#### 3. Factory
Factory contracts enable efficient deployment of Policies and Checkers. Implementations MUST:

- Support the [minimal proxy pattern with immutable args](https://github.com/Vectorized/solady/blob/main/src/utils/LibClone.sol).
- Ensure proper initialization of cloned contracts.
- Enable customizable deployment parameters.

---

## Preliminaries

### Access Control Mode
Excubiae implements an Attribute-Based Access Control (ABAC) model where access decisions are based on attributes associated with the Subject. This differs from Role-Based Access Control (RBAC) by allowing more flexible, fine-grained permissions based on arbitrary verifiable evidence rather than predefined roles.

### Attribute-based Verification
The verifiable data / proof must be provided as encoded `bytes` to ensure flexibility and future compatibility. The encoded data MUST serve to validate the full set of verifiable attributes specified in the Checker contract. This approach allows:

- Packaging of multiple validation parameters in a single parameter through encoding
- Protocol agnostic evidence validation
- Forward compatibility with new validation schemes
- Custom interpretation by specialized Checkers

### Private Evidence
The framework is designed to operate entirely on-chain, with all validation and enforcement occurring within the EVM environment. This ensures transparency and auditability. Privacy is tightly coupled with the evidence used: for example, a zero-knowledge proof brings privacy preserving verification for the prover (no disclosure of secrets) while passing a token identifier as evidence has no privacy at all.

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
The system MUST implement the following flow when a **subject** (i.e., EOA or smart contract address) attempts to access a protected **target** (i.e., smart contract protected method / resource). Note that the following steps are generic and assumes that Checker and Policy clones have been successfully deployed and initialized from respective Factory contracts.

1. Subject provides evidence to a policy.
2. Policy delegates validation to its checker.
3. Checker verifies the evidence.
4. Policy enforces the checker's decision & keeps track of the subject.

#### 1. Checker
A Checker in Excubiae is responsible for validating access conditions. Think of it as the rulebook that defines what constitutes valid access - it receives evidence and determines whether it meets the specified criteria. The checker remains deliberately stateless, focusing solely on validation logic. This design allows checkers to be shared across different policies and enables clear, auditable validation rules. The framework offers two checker variants: BaseChecker and AdvancedChecker.

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

