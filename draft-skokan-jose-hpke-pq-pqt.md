---
title: "JOSE HPKE PQ & PQ/T Algorithm Registrations"
abbrev: "JOSE HPKE PQ"
category: std

docname: draft-skokan-jose-hpke-pq-pqt-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Javascript Object Signing and Encryption"
keyword:
 - JOSE
 - HPKE
 - post-quantum
 - hybrid
 - ML-KEM
 - PQ
 - PQ/T
 - JWE
 - CRQC
venue:
  group: "Javascript Object Signing and Encryption"
  type: "Working Group"
  mail: "jose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/jose/"
  github: "panva/jose-hpke-pq-pqt"
  latest: "https://panva.github.io/jose-hpke-pq-pqt/draft-skokan-jose-hpke-pq-pqt.html"

author:
 -
    fullname: Filip Skokan
    organization: Okta
    email: panva.ip@gmail.com
 -
    fullname: Brian Campbell
    organization: Ping Identity
    email: bcampbell@pingidentity.com

normative:
  I-D.ietf-jose-hpke-encrypt:
  I-D.ietf-hpke-pq:
  I-D.ietf-cose-dilithium:

informative:
  RFC7518:

...

--- abstract

This document registers Post-Quantum (PQ) and Post-Quantum/Traditional (PQ/T)
hybrid algorithm identifiers for use with JSON Object Signing and Encryption
(JOSE), building on the Hybrid Public Key Encryption (HPKE) framework.


--- middle

# Introduction

{{I-D.ietf-jose-hpke-encrypt}} defines how to use Hybrid Public Key Encryption
(HPKE) with JSON Web Encryption (JWE) using traditional Key Encapsulation Mechanisms
(KEM) based on Elliptic-curve Diffie-Hellman (ECDH).

This document extends the set of registered HPKE algorithms to include Post-Quantum
(PQ) and Post-Quantum/Traditional (PQ/T) hybrid KEMs, as defined in
{{I-D.ietf-hpke-pq}}. These algorithms provide protection against attacks by
cryptographically relevant quantum computers.

The term “PQ/T hybrid” is used here consistent with {{I-D.ietf-hpke-pq}} to denote a
combination of post-quantum and traditional algorithms, and should not be confused
with HPKE’s use of “hybrid” to describe internal KEM composition.

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Algorithm Identifiers {#algorithm-identifiers}

This section defines the algorithm identifiers for PQ and PQ/T HPKE-based
encryption in JOSE. Each algorithm is defined by a combination of an HPKE KEM,
a Key Derivation Function (KDF), and an Authenticated Encryption with
Associated Data (AEAD) algorithm.

All algorithms defined in this section follow the same operational model as
those in {{I-D.ietf-jose-hpke-encrypt}}, supporting both integrated encryption
as defined in {{Section 5 of I-D.ietf-jose-hpke-encrypt}} and key encryption
as defined in {{Section 6 of I-D.ietf-jose-hpke-encrypt}}.

## PQ/T Hybrid Integrated Encryption Algorithms

The following table lists the algorithm identifiers for PQ/T hybrid integrated
encryption, where HPKE directly encrypts the plaintext without a separate
Content Encryption Key:

| "alg" value | HPKE KEM                    | HPKE KDF            | HPKE AEAD                   |
| ----------- | --------------------------- | ------------------- | --------------------------- |
| HPKE-8      | MLKEM768-P256 (`0x0050`)    | SHAKE256 (`0x0011`) | AES-256-GCM (`0x0002`)      |
| HPKE-9      | MLKEM768-P256 (`0x0050`)    | SHAKE256 (`0x0011`) | ChaCha20Poly1305 (`0x0003`) |
| HPKE-10     | MLKEM768-X25519 (`0x647a`)  | SHAKE256 (`0x0011`) | AES-256-GCM (`0x0002`)      |
| HPKE-11     | MLKEM768-X25519 (`0x647a`)  | SHAKE256 (`0x0011`) | ChaCha20Poly1305 (`0x0003`) |
| HPKE-12     | MLKEM1024-P384 (`0x0051`)   | SHAKE256 (`0x0011`) | AES-256-GCM (`0x0002`)      |
| HPKE-13     | MLKEM1024-P384 (`0x0051`)   | SHAKE256 (`0x0011`) | ChaCha20Poly1305 (`0x0003`) |
{: #pqt-hybrid-integrated-table title="PQ/T Hybrid Integrated Encryption Algorithms" }

These algorithms combine ML-KEM with a traditional elliptic curve algorithm in a PQ/T
hybrid KEM construction, providing security that is intended to remain robust against
both classical adversaries and adversaries with access to cryptographically relevant
quantum computers during the transition to post-quantum cryptography.

## Pure PQ Integrated Encryption Algorithms

The following table lists the algorithm identifiers for pure post-quantum
integrated encryption:

| "alg" value | HPKE KEM                 | HPKE KDF            | HPKE AEAD                   |
| ----------- | ------------------------ | ------------------- | --------------------------- |
| HPKE-14     | ML-KEM-768 (`0x0041`)    | SHAKE256 (`0x0011`) | AES-256-GCM (`0x0002`)      |
| HPKE-15     | ML-KEM-768 (`0x0041`)    | SHAKE256 (`0x0011`) | ChaCha20Poly1305 (`0x0003`) |
| HPKE-16     | ML-KEM-1024 (`0x0042`)   | SHAKE256 (`0x0011`) | AES-256-GCM (`0x0002`)      |
| HPKE-17     | ML-KEM-1024 (`0x0042`)   | SHAKE256 (`0x0011`) | ChaCha20Poly1305 (`0x0003`) |
{: #pure-pq-integrated-table title="Pure PQ Integrated Encryption Algorithms" }

These algorithms provide pure post-quantum security using ML-KEM without a
traditional algorithm component.

## PQ/T Hybrid Key Encryption Algorithms

The following table lists the algorithm identifiers for PQ/T hybrid key
encryption, where HPKE encrypts the Content Encryption Key:

| "alg" value | HPKE KEM                    | HPKE KDF            | HPKE AEAD                   |
| ----------- | --------------------------- | ------------------- | --------------------------- |
| HPKE-8-KE   | MLKEM768-P256 (`0x0050`)    | SHAKE256 (`0x0011`) | AES-256-GCM (`0x0002`)      |
| HPKE-9-KE   | MLKEM768-P256 (`0x0050`)    | SHAKE256 (`0x0011`) | ChaCha20Poly1305 (`0x0003`) |
| HPKE-10-KE  | MLKEM768-X25519 (`0x647a`)  | SHAKE256 (`0x0011`) | AES-256-GCM (`0x0002`)      |
| HPKE-11-KE  | MLKEM768-X25519 (`0x647a`)  | SHAKE256 (`0x0011`) | ChaCha20Poly1305 (`0x0003`) |
| HPKE-12-KE  | MLKEM1024-P384 (`0x0051`)   | SHAKE256 (`0x0011`) | AES-256-GCM (`0x0002`)      |
| HPKE-13-KE  | MLKEM1024-P384 (`0x0051`)   | SHAKE256 (`0x0011`) | ChaCha20Poly1305 (`0x0003`) |
{: #pqt-hybrid-key-encryption-table title="PQ/T Hybrid Key Encryption Algorithms" }

## Pure PQ Key Encryption Algorithms

The following table lists the algorithm identifiers for pure post-quantum key
encryption:

| "alg" value | HPKE KEM                 | HPKE KDF            | HPKE AEAD                   |
| ----------- | ------------------------ | ------------------- | --------------------------- |
| HPKE-14-KE  | ML-KEM-768 (`0x0041`)    | SHAKE256 (`0x0011`) | AES-256-GCM (`0x0002`)      |
| HPKE-15-KE  | ML-KEM-768 (`0x0041`)    | SHAKE256 (`0x0011`) | ChaCha20Poly1305 (`0x0003`) |
| HPKE-16-KE  | ML-KEM-1024 (`0x0042`)   | SHAKE256 (`0x0011`) | AES-256-GCM (`0x0002`)      |
| HPKE-17-KE  | ML-KEM-1024 (`0x0042`)   | SHAKE256 (`0x0011`) | ChaCha20Poly1305 (`0x0003`) |
{: #pure-pq-key-encryption-table title="Pure PQ Key Encryption Algorithms" }


# JSON Web Key Representation

Keys for the algorithms defined in this document use the "AKP" (Algorithm
Key Pair) key type defined in {{I-D.ietf-cose-dilithium}}.

For the algorithms in this document, the "pub" parameter contains the
base64url encoding of HPKE's SerializePublicKey() output for the
corresponding KEM, and the "priv" parameter contains the base64url encoding
of HPKE's SerializePrivateKey() output.


# Security Considerations

The security considerations of {{I-D.ietf-jose-hpke-encrypt}} and
{{I-D.ietf-hpke-pq}} apply to this document.


# IANA Considerations

## JSON Web Signature and Encryption Algorithms Registry

This document requests registration of the following values in the
IANA "JSON Web Signature and Encryption Algorithms" registry
established by {{RFC7518}}:

### HPKE-8

- Algorithm Name: HPKE-8
- Algorithm Description: Integrated Encryption with HPKE using MLKEM768-P256 KEM, SHAKE256 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pqt-hybrid-integrated-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-8-KE

- Algorithm Name: HPKE-8-KE
- Algorithm Description: Key Encryption with HPKE using MLKEM768-P256 KEM, SHAKE256 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pqt-hybrid-key-encryption-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-9

- Algorithm Name: HPKE-9
- Algorithm Description: Integrated Encryption with HPKE using MLKEM768-P256 KEM, SHAKE256 KDF, and ChaCha20Poly1305 AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pqt-hybrid-integrated-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-9-KE

- Algorithm Name: HPKE-9-KE
- Algorithm Description: Key Encryption with HPKE using MLKEM768-P256 KEM, SHAKE256 KDF, and ChaCha20Poly1305 AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pqt-hybrid-key-encryption-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-10

- Algorithm Name: HPKE-10
- Algorithm Description: Integrated Encryption with HPKE using MLKEM768-X25519 KEM, SHAKE256 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pqt-hybrid-integrated-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-10-KE

- Algorithm Name: HPKE-10-KE
- Algorithm Description: Key Encryption with HPKE using MLKEM768-X25519 KEM, SHAKE256 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pqt-hybrid-key-encryption-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-11

- Algorithm Name: HPKE-11
- Algorithm Description: Integrated Encryption with HPKE using MLKEM768-X25519 KEM, SHAKE256 KDF, and ChaCha20Poly1305 AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pqt-hybrid-integrated-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-11-KE

- Algorithm Name: HPKE-11-KE
- Algorithm Description: Key Encryption with HPKE using MLKEM768-X25519 KEM, SHAKE256 KDF, and ChaCha20Poly1305 AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pqt-hybrid-key-encryption-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-12

- Algorithm Name: HPKE-12
- Algorithm Description: Integrated Encryption with HPKE using MLKEM1024-P384 KEM, SHAKE256 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pqt-hybrid-integrated-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-12-KE

- Algorithm Name: HPKE-12-KE
- Algorithm Description: Key Encryption with HPKE using MLKEM1024-P384 KEM, SHAKE256 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pqt-hybrid-key-encryption-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-13

- Algorithm Name: HPKE-13
- Algorithm Description: Integrated Encryption with HPKE using MLKEM1024-P384 KEM, SHAKE256 KDF, and ChaCha20Poly1305 AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pqt-hybrid-integrated-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-13-KE

- Algorithm Name: HPKE-13-KE
- Algorithm Description: Key Encryption with HPKE using MLKEM1024-P384 KEM, SHAKE256 KDF, and ChaCha20Poly1305 AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pqt-hybrid-key-encryption-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-14

- Algorithm Name: HPKE-14
- Algorithm Description: Integrated Encryption with HPKE using ML-KEM-768 KEM, SHAKE256 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pure-pq-integrated-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-14-KE

- Algorithm Name: HPKE-14-KE
- Algorithm Description: Key Encryption with HPKE using ML-KEM-768 KEM, SHAKE256 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pure-pq-key-encryption-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-15

- Algorithm Name: HPKE-15
- Algorithm Description: Integrated Encryption with HPKE using ML-KEM-768 KEM, SHAKE256 KDF, and ChaCha20Poly1305 AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pure-pq-integrated-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-15-KE

- Algorithm Name: HPKE-15-KE
- Algorithm Description: Key Encryption with HPKE using ML-KEM-768 KEM, SHAKE256 KDF, and ChaCha20Poly1305 AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pure-pq-key-encryption-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-16

- Algorithm Name: HPKE-16
- Algorithm Description: Integrated Encryption with HPKE using ML-KEM-1024 KEM, SHAKE256 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pure-pq-integrated-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-16-KE

- Algorithm Name: HPKE-16-KE
- Algorithm Description: Key Encryption with HPKE using ML-KEM-1024 KEM, SHAKE256 KDF, and AES-256-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pure-pq-key-encryption-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-17

- Algorithm Name: HPKE-17
- Algorithm Description: Integrated Encryption with HPKE using ML-KEM-1024 KEM, SHAKE256 KDF, and ChaCha20Poly1305 AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pure-pq-integrated-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-17-KE

- Algorithm Name: HPKE-17-KE
- Algorithm Description: Key Encryption with HPKE using ML-KEM-1024 KEM, SHAKE256 KDF, and ChaCha20Poly1305 AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{pure-pq-key-encryption-table}} of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
