## Anon-Aadhaar spec raw

---

slug: CS-02
title: CS-02/ANON-AADHAAR-V2
name: Anonymous Aadhaar Verification Protocol
status: draft
category: Standards Track
editor: Yanis Meziane <yanis@pse.dev>
contributors:

- Saleel P <saleel@saleel.xyz>, Oskar Thoren <oskarth@titanproxy.com>
- tags:
  - zero-knowledge
  - identity
  - privacy

---

# Change Process

This document is governed by the [1/COSS](../1) (COSS).

# Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

# Abstract

Anon Aadhaar is a zero-knowledge protocol enabling privacy-preserving verification of the [Aadhaar Secure QR Code](https://uidai.gov.in/en/ecosystem/authentication-devices-documents/qr-code-reader.html). [Aadhaar](https://en.wikipedia.org/wiki/Aadhaar) is a unique identity system in India, issued by the government, containing a 12-digit identification number linked to an individual's biometric and demographic data. The Aadhaar Secure QR code is an offline KYC process where a legitimate Aadhaar identity owner can store a QR code representing their concatenated identity and a digital signature of it. The protocol leverages this digital signature to allow proving possession of valid UIDAI-issued Aadhaar documents without revealing personal information, using RSA-SHA256 signature verification in zero-knowledge combined with selective disclosure mechanisms.

# Motivation

Current Aadhaar verification methods expose sensitive personal data, as the verifier of the signature requires full access to the entire identity. This approach compromises user privacy and limits the applicability of Aadhaar in decentralized and trustless systems.

This protocol offers a solution for privacy-preserving and decentralized identity verification, addressing these challenges by enabling:

- **Privacy-preserving verification of government-issued identity**: Ensuring that sensitive personal data is not exposed during verification.
- **Selective disclosure of specific attributes**: Allowing users to reveal only the necessary attributes, such as age or residency, without disclosing the full identity.
- **Prevention of identity reuse through nullifiers**: Guaranteeing that identity proofs are unique and cannot be reused fraudulently.
- **Decentralized verification without trusted intermediaries**: Supporting verification on decentralized systems, such as validating proof of a valid Aadhaar on public decentralized system, like Byzantine system or a blockchain.

# Specification

## System Requirements

Implementations MUST provide:

### 1. SHA-256 Hashing

To process the plaintext data, the SHA-256 hash of the data must be computed within the circuit. This is necessary because the Aadhaar Secure QR Code signs the hash of the data, not the plaintext itself. The protocol leverages the SHA-256 hashing function, as it is currently used in Aadhaar Secure QR Code specifications.

### 2. RSA-2048 Signature Verification

The RSA-2048 signature verification must also be performed within the circuit. Constraining this process inside the circuit allows the proof to validate the correct execution of the signature verification against the specified public key. This ensures the authenticity of the signed data without exposing sensitive information.

### 3. QR Code Data Parsing and Selective Disclosure

Once the signature is verified, the protocol ensures the data is authenticated. At this stage, specific identity attributes can be selectively disclosed and extracted from the QR code data. These attributes include:

- Photo
- Birthdate
- Gender
- State
- Pincode
- Timestamp of the signature

For more details about data parsing, see [Appendix B - Data Formats](#Appendix-B-Data-Formats)

### 4. Nullifier Generation

A nullifier is a core component of the protocol, designed to generate a unique identifier for the user without revealing sensitive identity attributes. The nullifier is constructed using the following formula:

```
Hash(Photo || NullifierSeed)
```

#### Photo

The photo is used as it provides high entropy, reducing the risk of collision (e.g., two individuals generating the same nullifier). Using a photo also protects against dictionary attacks. For instance, a nullifier derived from simple attributes like name and birthdate could be easily recomputed, enabling tracking.

#### Nullifier Seed

The nullifier seed enables application- or action-specific nullifiers, ensuring that the same person generates distinct nullifiers across different applications or actions. This prevents cross-application linkage. The protocol recommends a nullifier seed of 16 bytes, allowing for \(2^{128}\) possible values.

---

## Preliminaries

### Proof Generation Environment

The protocol is built with the assumption that closed servers cannot be trusted. Consequently, proof generation must occur locally on the client’s device. Sensitive data is never shared with third parties during the proof generation process, preserving user privacy.

### Nullifier Assumptions

Nullifiers protect users from deanonymization by relying on the computational hardness of reversing a hash function. Only the issuer of the corresponding signature can feasibly link nullifiers, as they hold the original inputs. Additionally, since proof generation happens locally on the client, the nullifier seed is treated as public, maintaining privacy while ensuring robust linkage prevention.

### Selective Disclosure

The protocol does not allow arbitrary disclosure of identity attributes but instead ensures that only group-secure attributes are revealed. This approach guarantees that even when all disclosed attributes are revealed, they belong to a sufficiently large set to prevent deanonymization. The protocol is designed for identity verification on public, immutable networks, and it prevents any sensitive data from being published publicly.

## Protocol Flow

### 1. Document Processing

Implementations MUST:

1. Extract the signed message and the signature from the QR code data
2. Verify RSA-SHA256 signature
3. Parse signed data fields
4. Generate circuit inputs

Input requirements:

```
{
  qrDataPadded: Bytes,        // REQUIRED - QR code padded signed data
  qrDataPaddedLength: Bytes32 // REQUIRED - Length of the the QR code padded data
  signature: Bytes,           // REQUIRED - RSA signature
  pubKey: Bytes,              // REQUIRED - Public key
  nullifierSeed: Bytes32,     // REQUIRED - Random seed of the nullifier
  signalHash: Bytes32,        // OPTIONAL - Binding data
  ageAbove18: Boolean,        // OPTIONAL - Disclosure flags
  gender: Boolean,            // OPTIONAL - Disclosure flags
  state: Boolean,             // OPTIONAL - Disclosure flags
  pincode: Boolean            // OPTIONAL - Disclosure flags

}
```

## Circuit Design

The current circuit design is made to optimise its implementation using Circom Groth16, but note that the same logics could be applied and implemented in other proving schemes.

For more details, see [appendix A - Circuit Architecture](#Appendix-A-Circuit-Architecture)

### Inputs

#### Private Inputs

- `qrDataPadded: Bytes[]` - Padded signed data from QR code
- `qrDataPaddedLength: BigInt` - Length of the the QR code padded data
- `delimiterIndices: BigInt[]` - Set of the data delimiters
- `signature: BigInt[]` - RSA signature from QR code
- `pubKey: BigInt[]` - RSA public key

#### Optional Private Inputs

- `revealAgeAbove18: Boolean` - Flag to reveal age check
- `revealGender: Boolean` - Flag to reveal gender
- `revealState: Boolean` - Flag to reveal state
- `revealPincode: Boolean` - Flag to reveal pincode

#### Public Inputs

- `nullifierSeed: BigInt` - Random seed for nullifier generation
- `signalHash: BigInt` - Hash for binding external data

### Circuit Operations

The circuit MUST perform the following operations in sequence:

1. Signature Verification
   a. **SHA-256 Hash**

   - Input: `qrDataPadded`, `qrDataPaddedLength`
   - Output: Hash of signed data
   - Purpose: Prepare data for RSA verification; Note that by inserting the plaintext data instead of the hash in the circuit let us access the clear data.

   b. **RSA Signature Verification**

   - Input: SHA-256 hash, `signature`, `pubKey`
   - Verification: PKCS#1 v1.5 padding check
   - Purpose: Ensure authentic signature of the data from the inserted public key.

2. **Field Extraction**

   - Input: Verified `signedData`
   - Operations:
     - Extract photo bytes
     - Extract timestamp
     - IF `revealAgeAbove18`: Extract birthdate and verify age > 18, by comparing birthdate with the timestamp
     - IF `revealGender`: Extract gender
     - IF `revealState`: Extract state
     - IF `revealPincode`: Extract pincode

3. **Final Computations**
   - Nullifier Generation:
     - Input: `nullifierSeed`, photo bytes
     - Output: `nullifier: Bytes32 := Hash(nullifierSeed | photo)`
   - Timestamp Conversion:
     - Convert extracted timestamp to UTC UNIX
   - Signal Constraints:
     - Apply constraints on `signalHash`
   - Hash pubKey:
     - `pubkeyHash := Hash(pubKey)`

### Outputs

#### Required Outputs

- `nullifier: Bytes32` - Unique identifier derived from seed and photo
- `timestamp: Uint64` - UTC UNIX timestamp
- `pubKeyHash: Bytes32` - Hash of RSA public key

#### Optional Outputs (Only if requested)

- `ageAbove18: Boolean`
- `gender: BigInt`
- `state: BigInt`
- `pincode: BigInt`

### Component Interaction

![image](./anon-aadhaar-circuit.png)

### 2. Proof Generation

The proof generation MUST:

1. Verify QR data signature
2. Extract required fields
3. Generate nullifier
4. Create zero-knowledge proof

Circuit constraints:

1. RSA signature validity
2. Field bounds checking

Note that the circuit is agnostic in terms of RSA public key, it check generate a valid proof as soon as the data format correspond to the Aadhaar Secure QR code, it's the role of the verifier to check the correctness of the used RSA public key, and check that the outputed hash of the public key, is corresponding to one official UIDAI public key.

### 3. Verification

Verifier MUST check:

1. Proof validity
2. RSA public key validity

Verifier SHOULD check:

1. Nullifier uniqueness, by checking that the nullifier seed is the one corresponding to the action set.
2. Timestamp bounds, it should be used as a timebased one time password (TOTP), ensuring the user has access to the UIDAI portal and can generate freshly signed data.

Verifier OPTIONALLY check:

1. Signal Hash, verify that the signal commited to is corresponding to the expected value. This mechanism is useful to prevent front running when sending a proof to an on-chain verifier, the user can commit to an EOA address from which the transaction will be send.
2. Selective Disclosure, verify an attributes from the four revealed fields.

Output format:

```
{
  proof: Bytes,            // Zero-knowledge proof
  pubKeyHash: Bytes32,     // RSA key commitment
  timestamp: Uint64,       // UTC Unix timestamp
  nullifierSeed: string    // Seed of the nullifier
  nullifier: Bytes32,      // Unique identifier
  signalHash: Bytes32,     // Optional binding
  ageAbove18: Boolean       // Optional disclosures
  gender: string           // Optional disclosures
  pincode: string          // Optional disclosures
  state: string            // Optional disclosures
}
```

## Error Handling

Implementations MUST handle:

1. Invalid QR format
2. Invalid signature
3. Duplicate nullifier
4. Invalid proof

Error responses MUST include:

1. Error code
2. Error message
3. Error details (when available)

# Security Considerations

## Threat Model

The protocol assumes:

1. The proven security of the used proving system, and the trusted setup of the circuit if required by the proving system being used
2. Secure and honest UIDAI RSA key, the trusting the UIDAI RSA private key will not sign non legitimate identities

## Known limitations:

- Circuit Constraints Size
- Aadhaar Secure QR Code Format and Nullifier Rotation

**1. Circuit Size Constraints**

The current reference implementation in Circom comprises approximately **1 million constraints**. The benchmarks for this implementation are as follows:

- **Memory consumption at peak with bare metal Rapidsnark**: 1.4 GB
- **Proving key size**: 600 MB (to be downloaded)

**2. Considerations for Aadhaar Secure QR Code and Nullifier Rotation**

- **QR Code Format Changes**: The protocol does not have control on the signature generation process. If the Unique Identification Authority of India (UIDAI) modifies the format of the Aadhaar Secure QR code, the protocol must be updated to accommodate the new data serialization format. The Secure QR code contains demographic information and the photograph of the Aadhaar holder, digitally signed by UIDAI to ensure security and integrity.

- **Nullifier Rotation**: The nullifier is derived from the user's Aadhaar photo. UIDAI allows individuals to update their Aadhaar photograph by visiting an Aadhaar Enrolment Centre or Aadhaar Sewa Kendra. The process involves submitting a request and providing biometric details, with the update typically processed within 90 days. However, the actual time frame may vary, and users should consider the potential for generating multiple nullifiers within a short period if the photo is updated. This factor is crucial when developing use cases that require a nullifier to remain consistent for an extended duration.

## Privacy Guarantees

The protocol MUST guarantee:

1. That the user cannot be deanonymized, except from the issuer of the signature.
2. That the unique identifier of the user (nullifier) cannot be used to track user's activity as soon as the nullifier seed changes accross applications.

**Note**: While it cannot be enforced at the protocol level, the protocol strongly recommends that users SHOULD have access to a comprehensive UI that clearly displays what the prover is going to reveal when using selective disclosure and/or signal binding.

# Implementation Notes

The current [reference implementation](https://github.com/anon-aadhaar/anon-aadhaar) of the protocol is built with [Circom](https://docs.circom.io/) Groth16, and snarkjs.

Basic proof generation:

```typescript
// generateArgs is the component that will prepare the inputs for the circuit
// https://github.com/anon-aadhaar/anon-aadhaar/blob/main/packages/core/src/generateArgs.ts
const args = await generateArgs({
  qrData: QRData,
  certificateFile: certificate, // x509 PEM certificate of the signing public key
  nullifierSeed: number,
});

// Call to the snarkjs prove function
const anonAadhaarProof = await prove(args);
```

Basic verification:

```typescript
// Call to the snarkjs verify function
const verified = await verify(anonAadhaarProof);
```

# References

1. [UIDAI Aadhaar Secure QR Code Specification](https://uidai.gov.in/images/resource/User_manulal_QR_Code_15032019.pdf)
2. [RSA PKCS#1 v2.1](https://www.rfc-editor.org/rfc/rfc2313)
3. [SHA-256 FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.180-4.pdf)

# Appendix A: Circuit Architecture

## Components

### 1. AadhaarQRVerifier

**Description**: Verifies the Aadhaar QR data using RSA signature.

**Parameters**:

- `n`: RSA public key size per chunk.
- `k`: Number of chunks the RSA public key is split into.
- `maxDataLength`: Maximum length of the data.

**Inputs**:

- `qrDataPadded`: QR data without the signature; assumes elements to be bytes; remaining space is padded with 0.
- `qrDataPaddedLength`: Length of padded QR data.
- `delimiterIndices`: Indices of delimiters (255) in the QR text data. Includes 18 delimiters.
- `signature`: RSA signature.
- `pubKey`: RSA public key (of the government).
- `revealAgeAbove18`: Flag to reveal if age is above 18.
- `revealGender`: Flag to reveal extracted gender.
- `revealPinCode`: Flag to reveal extracted pin code.
- `revealState`: Flag to reveal extracted state.
- `nullifierSeed`: Random value used as input to compute the nullifier.
- `publicSignalHash`: Any message to commit to (as part of the proof).

**Outputs**:

- `pubkeyHash`: Poseidon hash of the RSA public key (after merging chunks).
- `nullifier`: Unique value derived from `nullifierSeed` and Aadhaar data.
- `timestamp`: Timestamp of when the data was signed (converted to Unix timestamp).
- `ageAbove18`: Boolean flag indicating age is above 18; 0 if not revealed.
- `gender`: Gender (`70` for Female, `77` for Male); 0 if not revealed.
- `pinCode`: Pin code as integer; 0 if not revealed.
- `state`: State packed as integer (reverse order); 0 if not revealed.

### 2. SignatureVerifier

**Description**: Verifies the Aadhaar signature.

**Parameters**:

- `n`: RSA public key size per chunk.
- `k`: Number of chunks the RSA public key is split into.
- `maxDataLength`: Maximum length of the data.

**Inputs**:

- `qrDataPadded`: QR data without the signature; each number represents ASCII byte; remaining space is padded with 0.
- `qrDataPaddedLength`: Length of padded QR data.
- `signature`: RSA signature.
- `pubKey`: RSA public key.

**Output**:

- `pubkeyHash`: Poseidon hash of the public key.

### 3. Nullifier

**Description**: Computes the nullifier for an Aadhaar identity.

**Inputs**:

- `photo`: The photo of the user with SHA padding.

**Output**:

- `nullifier`: Computed as `hash(nullifierSeed, hash(photo[0:15]), hash(photo[16:31]))`.

### 4. TimestampExtractor

**Description**: Extracts the timestamp when the QR was signed, rounded to the nearest hour.

**Inputs**:

- `nDelimitedData[maxDataLength]`: QR data where each delimiter is `255 * n`, where `n` is the order of the data.

**Outputs**:

- `timestamp`: Unix timestamp.
- `year`: Year of the signature.
- `month`: Month of the signature.
- `day`: Day of the signature.

### 5. AgeExtractor

**Description**: Extracts the date of birth from the Aadhaar QR data and returns it as a Unix timestamp.

**Parameters**:

- `maxDataLength`: Maximum length of the data.

**Inputs**:

- `nDelimitedData[maxDataLength]`: QR data where each delimiter is `255 * n`.
- `startDelimiterIndex`: Index of the delimiter after which the date of birth starts.
- `currentYear`: Current year to calculate age.
- `currentMonth`: Current month to calculate age.
- `currentDay`: Current day to calculate age.

**Output**:

- `out`: Unix timestamp representing the date of birth.

### 6. GenderExtractor

**Description**: Extracts the gender from the Aadhaar QR data.

**Inputs**:

- `nDelimitedDataShiftedToDob[maxDataLength]`: QR data where each delimiter is `255 * n` shifted to the DOB index.
- `startDelimiterIndex`: Index of the delimiter after which gender starts.

**Output**:

- `out`: Single byte number representing gender.

### 7. PinCodeExtractor

**Description**: Extracts the pin code from the Aadhaar QR data.

**Inputs**:

- `nDelimitedData[maxDataLength]`: QR data where each delimiter is `255 * n`.
- `startDelimiterIndex`: Index of the delimiter after which the pin code starts.
- `endDelimiterIndex`: Index of the delimiter up to which the pin code is present.

**Output**:

- `out`: Pin code as integer.

### 8. PhotoExtractor

**Description**: Extracts the photo from the Aadhaar QR data.

**Inputs**:

- `nDelimitedData[maxDataLength]`: QR data where each delimiter is `255 * n`.
- `startDelimiterIndex`: Index of the delimiter after which the photo starts.
- `endIndex`: Index of the last byte of the photo.

**Output**:

- `out`: Integer array (`int[33]`) representing the photo in big-endian order.

### 9. QRDataExtractor

**Description**: Extracts the name, date, gender, and photo from the Aadhaar QR data.

**Inputs**:

- `data[maxDataLength]`: QR data without the signature, padded.
- `qrDataPaddedLength`: Length of the padded QR data.
- `delimiterIndices[17]`: Indices of the delimiters in the QR data.

**Outputs**:

- `name`: Single field integer representing the name in big-endian order.
- `age`: Unix timestamp representing the date of birth.
- `gender`: Single byte number representing gender.
- `photo`: Photo of the user with SHA padding.

### 10. DigitBytesToTimestamp

**Description**: Converts a date string of format `YYYYMMDDHHMMSS` to a Unix timestamp.

**Parameters**:

- `maxYears`: Maximum year that can be represented.
- `includeHours`: Include hours (1) or round down to day (0).
- `includeMinutes`: Include minutes (1) or round down to hour (0).
- `includeSeconds`: Include seconds (1) or round down to minute (0).

**Inputs**:

- `in`: Input byte array representing the date string.

**Output**:

- `out`: Integer representing the Unix timestamp.

## Component Interaction

![image](https://hackmd.io/_uploads/Byb23aRfkx.png)

# Appendix B: Data Formats

## QR Code Format

Based on the UIDAI documentation referenced (User Manual QR Code 2019), the QR code encoding for Aadhaar involves binary data, with delimiters indicating the structure of encoded fields. Here's a technical breakdown to extract data based on delimiters (value 255):

### Steps for Data Extraction:

1. **Understand the Data Structure**:

   - The binary QR code data is organized into fields separated by the delimiter `255` (0xFF in hexadecimal).
   - Each field corresponds to a specific piece of Aadhaar information (e.g., name, gender, date of birth, etc.).

2. **Convert Binary Data to Array**:

   - Read the binary QR code data into a byte array.
   - Example: `binaryData = [byte1, byte2, ..., byteN]`.

3. **Iterate Through Byte Array**:

   - Loop through the byte array and identify indices where the value `255` appears.
   - Use these indices to fill the `delimitersIndices` array, that will help us parse the data inside of the circuit.

4. **Extract Fields**:

   - Use the `delimitersIndices` to slice the `qrDataPadded` array.

### **Aadhaar QR Code Data Schema (V2)**

- **Key Changes in V2**:

  1. The version identifier `V2` ([86, 50] in ASCII) is present before the first delimiter (`255`).
  2. Mobile/email hash is removed.
  3. The last 4 digits of the mobile number are included before the photo.
  4. A total of 16 fields, followed by the last 4 digits of the mobile number, photo data, and a signature.

- **Field Order**:
  | **Index** | **Field Name** | **Description** |
  |-----------|--------------------------------------|------------------------------------------------------|
  | 1 | Email/Mobile Present Bit Indicator | 0: None, 1: Email, 2: Mobile, 3: Both |
  | 2 | Reference ID | Last 4 digits of Aadhaar number and timestamp |
  | 3 | Name | Resident's full name |
  | 4 | Date of Birth | In `YYYY-MM-DD` format |
  | 5 | Gender | `M` (Male), `F` (Female), `T` (Transgender) |
  | 6 | Address > Care of (C/O) | Guardian/parent name |
  | 7 | Address > District | District name |
  | 8 | Address > Landmark | Landmark (if available) |
  | 9 | Address > House | House name/number |
  | 10 | Address > Location | Locality or location name |
  | 11 | Address > Pin code | Postal code of residence |
  | 12 | Address > Post office | Name of the post office |
  | 13 | Address > State | State/UT name |
  | 14 | Address > Street | Street name |
  | 15 | Address > Sub district | Sub-district name |
  | 16 | VTC (Village/Town/City) | Name of the village, town, or city |
  | 17 | Last 4 digits of the mobile number | Last 4 digits of registered mobile number |
  | 18 | Photo | Base64-encoded JPEG, from 18th `255` till end |
  | - | Signature | Last 256 bytes of the binary data |

---

# Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
