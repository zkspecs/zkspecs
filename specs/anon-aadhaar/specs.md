## Anon-Aadhaar spec raw

---

slug: CS-02
title: CS-02/ANON-AADHAAR-V2
name: Anonymous Aadhaar Verification Protocol
status: raw
category: Standards Track
editor: [Yanis Meziane] <yanis@pse.dev>
contributors:

- [@Saleelp, @Oskarth]
  tags:
- zero-knowledge
- identity
- privacy

---

# Change Process

This document is governed by the [1/COSS](https://rfc.vac.dev/spec/1/).

# Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

# Abstract

Anon Aadhaar is a zero-knowledge protocol enabling privacy-preserving verification of the Aadhaar Secure QR Code. The protocol allows proving possession of valid UIDAI-issued Aadhaar documents without revealing personal information, using RSA signature verification in zero-knowledge combined with selective disclosure mechanisms.

# Motivation

Current Aadhaar verification methods expose sensitive personal data. This specification provides:

- Privacy-preserving verification of government-issued identity
- Selective disclosure of specific attributes
- Prevention of identity reuse through nullifiers
- Decentralized verification without trusted intermediaries (e.g. verifying proof of a valid Aadhaar on the EVM)

# Specification

## System Requirements

Implementations MUST provide:

1. RSA-2048 signature verification
2. SHA-256 hashing
3. QR code data parsing
4. Secure random number generation

## Protocol Flow

### 1. Document Processing

Implementations MUST:

1. Extract the signed message and the signature from the QR code data
2. Verify RSA signature
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

![image](https://hackmd.io/_uploads/Byb23aRfkx.png)

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

1. Trusted setup for zero-knowledge system
2. Secure and honest UIDAI RSA key, the trust assumption is that the UIDAI RSA private key will not sign non legitimate identities
3. Secure random number generator
4. Honest verifier

Known limitations:

1. QR code format changes, if the UIDAI change the format of the Aadhaar Secure QR code, then the protocol must be updated to follow the new data serialization.
2. Circuit size constraints, the current reference implementation in Circom have around 1 million constraints
3. Nullifier rotation, the nullifier is based on the Aadhaar photo of the user, this photo can be changed following a process specified by the UIDAI. From the documentation, the photo can be changed within 7 days, meaning that a user could potentially generates 2 nullifiers using the same nullifier Seed. This must be took into consideration when building use cases that requires a nullifier lasting for more than 7 days.

## Privacy Guarantees

The protocol MUST guarantee:

1. Base identity privacy
2. Nullifier unlinkability, from all the actors except the issuer of the signature
3. Signal binding when requested

# Implementation Notes

Basic proof generation:

```typescript
const args = await generateArgs({
  qrData: QRData,
  certificateFile: certificate, // x509 PEM certificate of the signing public key
  nullifierSeed: number,
});

const anonAadhaarProof = await prove(args);
```

Basic verification:

```typescript
const verified = await verify(anonAadhaarProof);
```

# References

1. [UIDAI QR Code Specification](https://uidai.gov.in/images/resource/User_manulal_QR_Code_15032019.pdf)
2. RSA PKCS#1 v2.1
3. SHA-256 FIPS 180-4

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
   - Use these indices to fill the delimitersIndices array.

4. **Extract Fields**:

   - Use the indices of `255` as delimiters to slice the data array.
   - Each slice represents a field value.

5. **Decode Field Values**:

   - Field values may be encoded in UTF-8 or another character encoding. Decode accordingly.
   - If numeric, parse into numbers. If string data, interpret as text.

6. **Map to Aadhaar Fields**:
   - Map the extracted fields to their corresponding Aadhaar attributes, as defined in the documentation.
   - Attributes may include name, address, gender, date of birth, and more.

Based on the information provided, here's an updated technical explanation and code structure for parsing Aadhaar QR code data (V2) with the new schema:

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
