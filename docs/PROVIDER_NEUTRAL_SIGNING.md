# Additive signing of finalized MIME bytes

The maintainer accepted this design on 23 October 2026, conditional on backwards compatibility and an Angus-free SJM DKIM path.
The additive implementation is tracked under [#28](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/28), with downstream integration under
[SJM #855](https://github.com/bbottema/simple-java-mail/issues/855). It is introduced in 3.4.0; published 3.3.1 does not expose this API.

## Public entry point

Add `DkimByteSigner` in `org.simplejavamail.utils.mail.dkim`, independently from the Angus-bound legacy facade:

```java
DkimByteSigner signer = DkimByteSigner.builder()
    .signingDomain("example.com")
    .selector("mail")
    .privateKey(privateKey) // java.security.PrivateKey
    .signingAlgorithm(SigningAlgorithm.SHA256_WITH_ED25519)
    .bodyCanonicalization(Canonicalization.RELAXED)
    .identity("sender@example.com")
    .build();

byte[] signedMessage = signer.sign(finalizedMessageBytes);
```

The entry point is `public byte[] sign(byte[] finalizedMessage) throws DkimSigningException`.
The builder uses the existing signing and canonicalization enums and applicable choices for identity, length/copied-header tags,
domain-key checking and signed headers. It produces an immutable signer, with passive inspection before construction and validation of
configuration/key compatibility at `build()`. DNS checks happen at signing. Cryptographic state belongs to each call.

Input is a complete finalized RFC 5322 message. Return a new array containing the new DKIM header followed by every original input byte.
Do not parse and rebuild MIME, change Message-ID, select a transport or finalize application content. Applications retain ownership of their
keys and keep supplied inputs stable during an operation. The facade owns its configuration structure and returned arrays.

## Compatibility boundary

Both facades share one internal DKIM engine. Existing `DkimSigner` constructors/methods, `DkimMessage` and its Angus inheritance,
`sign(DkimMessage)` and `getEncodedBody()` subclass hooks, exceptions, resource ownership and existing working output remain supported.
Keep Java 8, package/module identity, dependency transitivity, legacy defaults, key formats and DNS policy. Do not remove Angus from the
legacy caller's transitive setup or add ambiguously overloaded methods to its facade.

The new facade and its engine must load and sign with Angus absent, without resolving legacy types through their public signatures.
Use explicit cryptographic provider instances on the new route, including DNS-key decoding/matching, without installing a JVM-global
provider. Preserve the legacy route's existing initialization behavior. Share DNS policy/cache machinery without making a neutral call
initialize the legacy provider path.

Keep upstream's relaxed-header/simple-body defaults; SJM explicitly maps its relaxed/relaxed defaults and existing signing choices.
Ed25519 signs the SHA-256 header digest required by [RFC 8463 section 3](https://www.rfc-editor.org/rfc/rfc8463.html#section-3).
RSA retains its existing hashing-signature behavior without an extra prehash. The new path preserves SJM's accepted case-insensitive
identity-domain comparison while the existing upstream facade retains its compatibility policy.

The existing line-ending and relaxed-whitespace policy issues #25/#26, SHA-1 policy, key-strength policy and stricter DNS interpretation
remain outside this work. Ordinary implementation does not authorize version changes, tags, publication or closure.

The durable signing-ownership decision belongs in SJM ADR 0008; concrete API details stay in this feature design. Governing records are [ADR 0007](https://github.com/bbottema/simple-java-mail/blob/codex/10.0.0/docs/adr/0007-provider-neutral-mime-boundary.md)
and [ADR 0008](https://github.com/bbottema/simple-java-mail/blob/codex/10.0.0/docs/adr/0008-minimal-mime-structures-and-protection-order.md).
