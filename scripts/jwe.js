import { CipherSuite } from "hpke";
import { algorithms } from "./algorithms.js";

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createCipheriv, randomBytes } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const jwksDir = join(__dirname, "..", "examples", "jwks");
const outDir = join(__dirname, "..", "examples", "jwe");
mkdirSync(outDir, { recursive: true });

function base64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function base64urlDecode(str) {
  return new Uint8Array(Buffer.from(str, "base64url"));
}

const plaintext =
  "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

const aadString = "The Fellowship of the Ring";

// Build the Recipient_structure for Key Encryption
// "JOSE-HPKE rcpt" || 0xFF || ASCII(enc) || 0xFF || recipient_extra_info
function recipientStructure(contentEncAlg) {
  const prefix = new TextEncoder().encode("JOSE-HPKE rcpt");
  const separator = new Uint8Array([0xff]);
  const algBytes = new TextEncoder().encode(contentEncAlg);
  const result = new Uint8Array(prefix.length + 1 + algBytes.length + 1);
  result.set(prefix, 0);
  result.set(separator, prefix.length);
  result.set(algBytes, prefix.length + 1);
  result.set(separator, prefix.length + 1 + algBytes.length);
  return result;
}

// content encryption for Key Encryption mode
function encryptContent(cipherName, cek, plaintext, aad) {
  const iv = randomBytes(12);
  const cipher = createCipheriv(cipherName, cek, iv);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return { iv, ciphertext: encrypted, tag };
}

for (const { alg, kem, kdf, aead } of algorithms) {
  const isKeyEncryption = alg.endsWith("-KE");

  // Load the JWK
  const jwk = JSON.parse(readFileSync(join(jwksDir, `${alg}.json`), "utf8"));

  // Create the HPKE cipher suite and deserialize the public key
  const suite = new CipherSuite(kem, kdf, aead);
  const publicKey = await suite.DeserializePublicKey(base64urlDecode(jwk.pub));

  if (isKeyEncryption) {
    // === Key Encryption Mode ===
    // Determine "enc" and CEK size from the HPKE AEAD
    let enc, cekSize, cipherName;
    switch (suite.AEAD.id) {
      case 0x0001: // AES-128-GCM
        enc = "A128GCM";
        cekSize = 16;
        cipherName = "aes-128-gcm";
        break;
      case 0x0002: // AES-256-GCM
      case 0x0003: // ChaCha20Poly1305 does not have a jwe "enc"
        enc = "A256GCM";
        cekSize = 32;
        cipherName = "aes-256-gcm";
        break;
      default:
        throw new Error("unreachable");
    }

    // Generate a random CEK
    const cek = randomBytes(cekSize);

    // HPKE info = Recipient_structure
    const info = recipientStructure(enc);

    // HPKE Seal encrypts the CEK
    // HPKE aad defaults to empty for Key Encryption
    const { encapsulatedSecret, ciphertext: encryptedKey } = await suite.Seal(
      publicKey,
      cek,
      { info },
    );

    // --- Flattened JWE JSON with AAD ---
    {
      const protectedHeader = {
        alg,
        kid: jwk.kid,
        enc,
        ek: base64url(encapsulatedSecret),
      };
      const protectedHeaderB64 = base64url(
        new TextEncoder().encode(JSON.stringify(protectedHeader)),
      );
      const aadB64 = base64url(new TextEncoder().encode(aadString));

      // AAD for content encryption: ASCII(protected || '.' || aad)
      const contentAad = new TextEncoder().encode(
        protectedHeaderB64 + "." + aadB64,
      );

      const {
        iv,
        ciphertext: contentCiphertext,
        tag,
      } = encryptContent(cipherName, cek, plaintext, contentAad);

      const flattenedJwe = {
        protected: protectedHeaderB64,
        aad: aadB64,
        iv: base64url(iv),
        ciphertext: base64url(contentCiphertext),
        tag: base64url(tag),
        encrypted_key: base64url(encryptedKey),
      };

      const filename = join(outDir, `${alg}-flattened.json`);
      writeFileSync(filename, JSON.stringify(flattenedJwe, null, 2) + "\n");
    }

    // --- Compact JWE ---
    {
      // Need a fresh HPKE encryption for compact since encapsulated secret
      // is bound to a new key schedule
      const {
        encapsulatedSecret: compactEnc,
        ciphertext: compactEncryptedKey,
      } = await suite.Seal(publicKey, cek, { info });

      const protectedHeader = {
        alg,
        kid: jwk.kid,
        enc,
        ek: base64url(compactEnc),
      };
      const protectedHeaderB64 = base64url(
        new TextEncoder().encode(JSON.stringify(protectedHeader)),
      );

      // AAD for content encryption: ASCII(protected)
      const contentAad = new TextEncoder().encode(protectedHeaderB64);

      const {
        iv,
        ciphertext: contentCiphertext,
        tag,
      } = encryptContent(cipherName, cek, plaintext, contentAad);

      const compact = [
        protectedHeaderB64,
        base64url(compactEncryptedKey),
        base64url(iv),
        base64url(contentCiphertext),
        base64url(tag),
      ].join(".");

      const filename = join(outDir, `${alg}-compact.txt`);
      writeFileSync(filename, compact + "\n");
    }
  } else {
    // === Integrated Encryption Mode ===

    // --- Flattened JWE JSON with AAD ---
    {
      const protectedHeader = { alg, kid: jwk.kid };
      const protectedHeaderB64 = base64url(
        new TextEncoder().encode(JSON.stringify(protectedHeader)),
      );
      const aadB64 = base64url(new TextEncoder().encode(aadString));

      // HPKE aad = ASCII(Encoded Protected Header || '.' || BASE64URL(JWE AAD))
      const hpkeAad = new TextEncoder().encode(
        protectedHeaderB64 + "." + aadB64,
      );

      const { encapsulatedSecret, ciphertext } = await suite.Seal(
        publicKey,
        new TextEncoder().encode(plaintext),
        { aad: hpkeAad },
      );

      const flattenedJwe = {
        protected: protectedHeaderB64,
        aad: aadB64,
        encrypted_key: base64url(encapsulatedSecret),
        ciphertext: base64url(ciphertext),
      };

      const filename = join(outDir, `${alg}-flattened.json`);
      writeFileSync(filename, JSON.stringify(flattenedJwe, null, 2) + "\n");
    }

    // --- Compact JWE ---
    {
      const protectedHeader = { alg, kid: jwk.kid };
      const protectedHeaderB64 = base64url(
        new TextEncoder().encode(JSON.stringify(protectedHeader)),
      );

      // HPKE aad = ASCII(Encoded Protected Header) for compact (no JWE AAD)
      const hpkeAad = new TextEncoder().encode(protectedHeaderB64);

      const { encapsulatedSecret, ciphertext } = await suite.Seal(
        publicKey,
        new TextEncoder().encode(plaintext),
        { aad: hpkeAad },
      );

      // Compact: protected.encrypted_key.iv.ciphertext.tag
      // For integrated encryption: IV and tag are empty
      const compact = [
        protectedHeaderB64,
        base64url(encapsulatedSecret),
        "",
        base64url(ciphertext),
        "",
      ].join(".");

      const filename = join(outDir, `${alg}-compact.txt`);
      writeFileSync(filename, compact + "\n");
    }
  }
}
