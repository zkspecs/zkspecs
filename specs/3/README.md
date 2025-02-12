---

slug: 3
title: 3/Semaphore
name: Semaphore Protocol
status: draft
category: Standards Track
tags: zero-knowledge, identity, privacy, anonymity, proof of membership, groups
editor: Vivian Plasencia <vivianpc@pse.dev>
contributors:

- Andy <andy@pse.dev>
- Cedoor <cedoor@pse.dev>
- Oskar Thoren <oskarth@titanproxy.com>
- tags:
  - zero-knowledge
  - identity
  - groups
  - privacy

---

# Semaphore Specification

## Change Process

This document is governed by the [1/COSS](https://github.com/zkspecs/zkspecs/tree/main/specs/1) (COSS).

## Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

## Abstract

Semaphore is a [zero-knowledge](https://en.wikipedia.org/wiki/Zero-knowledge_proof) (zk) protocol that allows users to prove their membership in a group and send messages such as votes or feedback without revealing their identity.

It also provides a simple mechanism to prevent [double-signaling](#signaling), which means that the same proof cannot be verified twice.

## Motivation

Privacy remains a significant challenge in the digital world, with existing solutions often being limited, hard to extend, and overly complex. These limitations make it difficult to create privacy-preserving applications and prevent users from securely interacting without exposing their identities. Semaphore addresses these issues by enabling the sharing of anonymous [messages](#message), solving the critical need for privacy while maintaining transparency.

## System Components

Implementations MUST provide:

### 1. Identity

An identity serves as a unique identifier for users.

### 2. Group

A group is a collection of identities represented in a structured format.

### 3. Anonymous Proof of Membership

An anonymous proof of membership enables users to prove their inclusion in a group without revealing their identity.

### 4. Nullifier

A value designed to be a unique identifier for the zk proof. It is generated using the identity.

### 5. Anonymous Message

After joining a group and proving that they are part of it, users can also send an anonymous message.

## Interaction of System Components

Semaphore Flow:

1. The user generates an identity.
2. The identity is added to the group.
3. An anonymous membership proof can be generated using the identity and group.
4. A nullifier is generated to uniquely represent the user's zk proof while ensuring anonymity.
5. The user can attach an anonymous message (such as a vote, text message).

<div style="text-align: center;">
    <img src="./images/system-components.svg" alt="Description of SVG" width="500" height="500">
</div>

## Implementation

The implementation section will refer to [Semaphore v4](https://github.com/semaphore-protocol/semaphore/releases/tag/v4.0.0) implemented by [PSE](https://pse.dev/).

Semaphore's zk functionality is implemented using [Circom](https://github.com/iden3/circom) + [Snarkjs](https://github.com/iden3/snarkjs) + [Groth16](https://eprint.iacr.org/2016/260.pdf).

- **Circom**: Used to write the circuit and generate its [R1CS constraint system](https://docs.circom.io/background/background/#_1).
- **Snarkjs**: Used to generate [zk-artifacts](#zk-artifacts) as well as to create and verify zk-SNARK proofs.
- **Groth16**: Used as a proving system.

### Semaphore Identity

The identity of a user in the Semaphore protocol. A Semaphore identity consists of an [EdDSA](https://en.wikipedia.org/wiki/EdDSA) public/private key pair and a commitment. Semaphore uses an [EdDSA implementation](https://github.com/privacy-scaling-explorations/zk-kit/tree/main/packages/eddsa-poseidon) based on [Baby Jubjub](https://eips.ethereum.org/EIPS/eip-2494) and [Poseidon](https://www.poseidon-hash.info/).

#### Identity Commitment

The Identity Commitment is the public Semaphore identity value used in Semaphore groups. Semaphore uses the Poseidon hash function to create the identity commitment from the Semaphore identity public key.

### Semaphore Group

A [Semaphore group](https://github.com/semaphore-protocol/semaphore/tree/main/packages/group) is a Merkle tree in which each leaf is an identity commitment for a user.

Semaphore uses the **LeanIMT** implementation, which is an optimized binary incremental Merkle tree. The tree nodes are calculated using Poseidon. To learn more about it you can read the [LeanIMT paper](https://github.com/privacy-scaling-explorations/zk-kit/tree/main/papers/leanimt).

### Circuit

![Semaphore v4 Circuit Colors](./images/semaphore-v4-circuit-colors.svg)

#### Private Inputs

- `merkleProofLength`: Length of the Merkle Proof (Siblings Length) used to calculate the Merkle Root.
- `merkleProofSiblings`: Merkle Proof Siblings used to calculate the Merkle Root.
- `merkleProofIndices`: Merkle Proof Indices used to calculate the Merkle Root.
- `secret`: The secret is the scalar generated from the EdDSA private key. Using the secret scalar instead of the private key allows this circuit to skip steps 1, 2, 3 in the generation of the public key defined in [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5), making the circuit more efficient and simple. See the [Semaphore identity package](https://github.com/semaphore-protocol/semaphore/tree/main/packages/identity) to know more about how the identity is generated.

#### Public Inputs

- `message`: The value the user shares when voting, confirming, sending a text message, etc.
- `scope`: A value used like a topic on which users can generate a valid proof only once. The scope is supposed to be used to generate the nullifier.

#### Outputs

- `merkleRoot`: Merkle Root of the LeanIMT.
- `nullifier`: A value designed to be a unique identifier for the zk proof. It is used to prevent the same zk proof from being used twice. In Semaphore, the nullifier is the hash of the scope and secret value of the user's Semaphore identity.

When using the same scope for an identity, the resulting nullifier remains the same because the same hash is generated. To obtain different nullifiers for the same identity (allowing users to share multiple zk proofs) users must use a different scope each time.

The hash function used in the circuit is Poseidon because it is a zk-friendly hash function.

### Proof Generation

Snarkjs is used to generate the proof.

```ts
const { proof, publicSignals } = await groth16.fullProve(
  {
    secret: identity.secretScalar,
    merkleProofLength,
    merkleProofIndices,
    merkleProofSiblings,
    scope: hash(scope),
    message: hash(message)
  },
  wasm,
  zkey
)

return {
  merkleTreeDepth,
  merkleTreeRoot: merkleProof.root.toString(),
  nullifier: publicSignals[1],
  message: message.toString() as NumericString,
  scope: scope.toString() as NumericString,
  points: packGroth16Proof(proof)
}
```

To learn more about the proof generation, see the [proof generation code](https://github.com/semaphore-protocol/semaphore/blob/main/packages/proof/src/generate-proof.ts).

#### Semaphore Proof Example

```bash
{
  merkleTreeDepth: 10,
  merkleTreeRoot: '4990292586352433503726012711155167179034286198473030768981544541070532815155',
  nullifier: '17540473064543782218297133630279824063352907908315494138425986188962403570231',
  message: '32745724963520510550185023804391900974863477733501474067656557556163468591104',
  scope: '37717653415819232215590989865455204849443869931268328771929128739472152723456',
  points: [
    '21668337069844646813015291115284438234607322052337623326830707330064154913250',
    '5484905467799538881631237123282286864306155680753671338313686933143657835972',
    '16129789229127169079253218689550197285028424883172925653046098078118792423164',
    '20777706122379854993524659601832014684665489694335277047215897593373874956681',
    '6697558559751679943942291885282718275907555268106795371542167431979105110434',
    '19709269142703129641057076037387702381970592578248722843989118216760760132874',
    '17493422037248079872314969622558990504818232868144223100447800353776555945950',
    '20398320346518400096197920333973312490517624241764728676355205902471625807914'
  ]
}
```

### Proof Verification

Proof verification works both off-chain and on-chain (on [EVM-compatible chains](#evm-compatible-chains) where the Groth16 Semaphore verifier can be deployed).

#### Off-chain

Snarkjs is used to verify the proof.

```ts
return groth16.verify(
  verificationKey,
  [merkleTreeRoot, nullifier, hash(message), hash(scope)],
  unpackGroth16Proof(points)
)
```

To learn more about the proof verification in TypeScript/JavaScript, see [the proof verification code](https://github.com/semaphore-protocol/semaphore/blob/main/packages/proof/src/verify-proof.ts).

#### On-chain

Snarkjs is used to generate a Solidity verifier per tree depth. Then, all verifiers are merged into a single one. To know more about the verifier see the [Semaphore Verifier](https://github.com/semaphore-protocol/semaphore/blob/main/packages/contracts/contracts/base/SemaphoreVerifier.sol).

```solidity
return
    verifier.verifyProof(
        [proof.points[0], proof.points[1]],
        [[proof.points[2], proof.points[3]], [proof.points[4], proof.points[5]]],
        [proof.points[6], proof.points[7]],
        [proof.merkleTreeRoot, proof.nullifier, _hash(proof.message), _hash(proof.scope)],
        proof.merkleTreeDepth
    );
```

### Implementation Notes

- Identity generation SHOULD be performed off-chain, in the user's device.
- Semaphore proof generation SHOULD be performed off-chain, in the user's device.

### Limitations of the implementation

- **Scalability**: As the number of members grows, generating a client-side Merkle proof is no longer feasible. It’s necessary to have a server to do it. This not only is time and data consuming, but could also allow the server to deanonymize the proofs.
- **On-chain costs**: As the tree grows on-chain, the gas cost of insertions also increases.
- **zk-artifacts**: People need to download [zk-artifacts](#zk-artifacts) to generate the zk proof and these have a couple of megabytes which can be an issue with very slow internet connection.

#### Benchmarks

Benchmarks for the LeanIMT can be found in the [LeanIMT paper](https://github.com/privacy-scaling-explorations/zk-kit/tree/main/papers/leanimt).

Benchmarks for Semaphore are available in the [Semaphore documentation](https://docs.semaphore.pse.dev/benchmarks).

## Privacy Guarantees

The protocol MUST guarantee:

- Private Identity values remain private and controlled by their owners.
- The identity cannot be linked to the message.
- The identity cannot be revealed while generating the zk proof.

## References

1. [Semaphore Whitepaper](https://semaphore.pse.dev/whitepaper-v1.pdf)
2. [Semaphore GitHub organization](https://github.com/semaphore-protocol)
3. [Semaphore repository](https://github.com/semaphore-protocol/semaphore)

## Glossary

### Message

In Semaphore, the term message (also known as _signal_) refers to the value a user shares when performing actions such as voting, confirming, sending a text message, and more.

### Signaling

The act of sharing a message (e.g., a text message or vote).

### zk-Artifacts

zk-artifacts are the collection of files generated during:

- **Circuit compilation** in Circom (e.g., `.r1cs`, `.wasm` for circuit definition).
- **Proving system setup** (e.g., Groth16), including trusted setup ceremony files such as:
  - Proving and verification keys (`.zkey`)
  - The verification key in JSON format.

In this document, **zk-artifacts** specifically refer to:

- `.wasm`
- `.zkey`
- The verification key file in JSON format.

These zk-artifacts are used for:

- **Generating** zero-knowledge proofs (`.wasm`, `.zkey`).
- **Verifying** zero-knowledge proofs (verification key in JSON format).

### EVM-Compatible Chains

EVM-compatible chains are blockchain networks that support the Ethereum Virtual Machine (EVM), allowing them to run Ethereum-based smart contracts and decentralized applications (dApps) without modification. These chains maintain compatibility with Ethereum’s tooling, such as wallets, development frameworks, and infrastructure, enabling seamless deployment and interoperability across ecosystems.

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
