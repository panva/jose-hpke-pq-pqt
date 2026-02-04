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

normative:
  RFC7516:
  RFC7517:
  RFC7518:
  I-D.ietf-jose-hpke-encrypt:
  I-D.ietf-hpke-pq:
  I-D.ietf-cose-dilithium:

informative:

...

--- abstract

This document registers Post-Quantum (PQ) and Post-Quantum/Traditional (PQ/T)
hybrid algorithm identifiers for use with JSON Object Signing and Encryption
(JOSE) and JSON Web Encryption (JWE), building on the Hybrid Public Key
Encryption (HPKE) framework defined in {{I-D.ietf-jose-hpke-encrypt}}.


--- middle

# Introduction

{{I-D.ietf-jose-hpke-encrypt}} defines how to use Hybrid Public Key Encryption
(HPKE) with JSON Web Encryption (JWE). That specification registers algorithm
identifiers for traditional (non-post-quantum) KEMs based on elliptic curve
Diffie-Hellman.

This document extends the set of registered algorithms to include Post-Quantum
(PQ) and Post-Quantum/Traditional (PQ/T) hybrid KEMs, as defined in
{{I-D.ietf-hpke-pq}}. These algorithms provide protection against attacks by
cryptographically relevant quantum computers.

All algorithms defined in this document follow the same operational model as
those in {{I-D.ietf-jose-hpke-encrypt}}, supporting both integrated encryption
(where HPKE directly protects the plaintext) and key encryption (where HPKE
protects a Content Encryption Key).


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Algorithm Identifiers

This section defines the algorithm identifiers for PQ and PQ/T HPKE-based
encryption in JOSE.

## Integrated Encryption Algorithms

The following table lists the algorithm identifiers for integrated encryption,
where HPKE directly encrypts the plaintext without a separate Content
Encryption Key:

| "alg" value | HPKE KEM | HPKE KDF | HPKE AEAD |
|-------------|----------|----------|-----------|
| HPKE-8 | ML-KEM-768 | HKDF-SHA256 | AES-128-GCM |
| HPKE-9 | MLKEM768-X25519 | HKDF-SHA256 | AES-128-GCM |

HPKE-8 provides pure post-quantum security using ML-KEM-768.

HPKE-9 provides hybrid post-quantum/traditional security by combining
ML-KEM-768 with X25519, ensuring protection against both classical and
quantum adversaries.

When using integrated encryption algorithms, the "enc" (encryption algorithm)
Header Parameter MUST NOT be present, as specified in {{I-D.ietf-jose-hpke-encrypt}}.

## Key Encryption Algorithms

The following table lists the algorithm identifiers for key encryption, where
HPKE encrypts the Content Encryption Key (CEK):

| "alg" value | HPKE KEM | HPKE KDF | HPKE AEAD |
|-------------|----------|----------|-----------|
| HPKE-8-KE | ML-KEM-768 | HKDF-SHA256 | AES-128-GCM |
| HPKE-9-KE | MLKEM768-X25519 | HKDF-SHA256 | AES-128-GCM |

Key encryption algorithms are used with the "enc" Header Parameter to specify
the content encryption algorithm, as defined in {{RFC7516}}.


# JSON Web Key Representation

Keys for the algorithms defined in this document use the "AKP" (Asymmetric
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
- Algorithm Description: Integrated Encryption with HPKE using ML-KEM-768 KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): (#algorithm-identifiers) of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-8-KE

- Algorithm Name: HPKE-8-KE
- Algorithm Description: Key Encryption with HPKE using ML-KEM-768 KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): (#algorithm-identifiers) of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-9

- Algorithm Name: HPKE-9
- Algorithm Description: Integrated Encryption with HPKE using MLKEM768-X25519 KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): (#algorithm-identifiers) of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}

### HPKE-9-KE

- Algorithm Name: HPKE-9-KE
- Algorithm Description: Key Encryption with HPKE using MLKEM768-X25519 KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): (#algorithm-identifiers) of this document
- Algorithm Analysis Documents(s): {{I-D.ietf-hpke-pq}}


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
