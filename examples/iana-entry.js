export default function ianaEntry(entry) {
  const { alg, isKE, specTable, suite } = entry;
  const mode = isKE ? "Key Encryption" : "Integrated Encryption";

  return `### ${alg}
{: toc="exclude"}

- Algorithm Name: ${alg}
- Algorithm Description: ${mode} with HPKE using ${suite.KEM.name} KEM, ${suite.KDF.name} KDF, and ${suite.AEAD.name} AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{${specTable}}} of this document
- Algorithm Analysis Document(s): {{I-D.ietf-hpke-pq}}`;
}
