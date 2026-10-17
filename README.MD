[![Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE-2.0.txt)
[![Maven Central](https://img.shields.io/maven-central/v/org.simplejavamail/utils-mail-dkim.svg)](https://central.sonatype.com/artifact/org.simplejavamail/utils-mail-dkim)
[![Javadoc](https://www.javadoc.io/badge/org.simplejavamail/utils-mail-dkim.svg)](https://www.javadoc.io/doc/org.simplejavamail/utils-mail-dkim)

# utils-mail-dkim

DKIM signing and sending-domain key validation for Jakarta Mail and Angus Mail. Configure a signer, wrap a `MimeMessage`, and send it through your existing Jakarta Mail transport.

- Sign MIME messages with RSA-SHA256 and configurable signing algorithms.
- Configure simple or relaxed canonicalization independently for headers and body.
- Check the published DNS key against the signing key and identity before signing; enabled by default.
- Keep using standard Jakarta Mail message creation and transport APIs.

This library signs outgoing messages and checks domain-key records. It does not verify signatures on received messages or implement SPF or DMARC policy.

[Quick start](#quick-start) · [DNS setup](#publish-an-rsa-domain-key) · [Configuration](#configuration-and-defaults) · [Javadoc](https://www.javadoc.io/doc/org.simplejavamail/utils-mail-dkim) · [Changelog](CHANGELOG.md) · [Compatibility](docs/COMPATIBILITY.md) · [Maintainer workflow](MAINTAINER_WORKFLOW.md)

## Installation

```xml
<dependency>
    <groupId>org.simplejavamail</groupId>
    <artifactId>utils-mail-dkim</artifactId>
    <version>3.3.1</version>
</dependency>
```

The library targets Java 8 and uses `jakarta.mail` APIs. Its dependencies include Jakarta Mail API, Angus Mail, and Bouncy Castle. For JPMS applications, the JAR declares the automatic module name `org.simplejavamail.utils.mail.dkim`.

`3.3.1` is a patch release with no caller migration. See the [release notes](CHANGELOG.md#331-17-october-2026) for the corrected signing and DNS behavior.

## Quick start

Use your existing SMTP `Session` and an RSA private key in **unencrypted PKCS#8 DER** format. Publish the matching public key at `mail._domainkey.example.com` before sending.

```java
import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import org.simplejavamail.utils.mail.dkim.DkimMessage;
import org.simplejavamail.utils.mail.dkim.DkimSigner;

import java.io.File;

public class SignedMail {
    // Configure once and reuse for messages signed by this domain and selector.
    public static DkimSigner createSigner(File privateKey) throws Exception {
        DkimSigner signer = new DkimSigner("example.com", "mail", privateKey);
        signer.setIdentity("sender@example.com");
        return signer;
    }

    public static void send(Session session, DkimSigner signer) throws Exception {
        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress("sender@example.com"));
        message.setRecipient(Message.RecipientType.TO,
                new InternetAddress("recipient@example.net"));
        message.setSubject("A signed message", "UTF-8");
        message.setText("Hello from Jakarta Mail.", "UTF-8");

        Transport.send(new DkimMessage(message, signer));
    }
}
```

`DkimMessage` is an Angus `SMTPMessage` and can be passed to normal Jakarta Mail transport APIs. The signature is generated when the message is serialized, for example during `Transport.send(...)` or `writeTo(...)`. DNS validation and signing failures therefore occur at that point, rather than when the wrapper is constructed.

Finish configuring the signer before sharing it. Create a separate `DkimMessage` for each message and let it write the signed content; changes made by a downstream relay to signed headers or body can invalidate the signature.

## Configuration and defaults

Existing setters are optional; a new RSA signer uses the following defaults:

| Setting | Default | Configuration |
| --- | --- | --- |
| Signing algorithm | `SHA256_WITH_RSA` | `setSigningAlgorithm(...)` |
| Header canonicalization | `RELAXED` | `setHeaderCanonicalization(...)` |
| Body canonicalization | `SIMPLE` | `setBodyCanonicalization(...)` |
| Domain-key check | Enabled | `setCheckDomainKey(...)` |
| Identity (`i=`) | Omitted | `setIdentity(...)` |
| Body length (`l=`) | Omitted | `setLengthParam(...)` |
| Header-field copies (`z=`) | Omitted | `setCopyHeaderFields(...)` |

For example, to change canonicalization while retaining the other defaults:

```java
signer.setHeaderCanonicalization(Canonicalization.RELAXED);
signer.setBodyCanonicalization(Canonicalization.RELAXED);
```

`Canonicalization` and `SigningAlgorithm` are in `org.simplejavamail.utils.mail.dkim`.

The default header set covers addressing, subject, date, message identifiers, MIME metadata, reply/reference fields, and mailing-list headers when present. Use `addHeaderToSign(...)` and `removeHeaderToSign(...)` to customize it. `From` is mandatory and cannot be removed. See [DkimSigner Javadoc](https://www.javadoc.io/doc/org.simplejavamail/utils-mail-dkim/latest/org/simplejavamail/utils/mail/dkim/DkimSigner.html) for the API.

The file and stream constructors load RSA PKCS#8 DER keys; the stream constructor closes its input. Alternatively, pass an `RSAPrivateKey` directly. The Ed25519 constructor accepts Bouncy Castle's `EdDSAPrivateKey` and selects `SHA256_WITH_ED25519`. The algorithm must match the key type. The Ed25519 path signs the SHA-256 header hash and accepts standard raw DNS public keys, retaining legacy X.509 key support.

`SHA1_WITH_RSA` remains available for compatibility. Use RSA-SHA256 for new RSA deployments: [RFC 8301](https://www.rfc-editor.org/rfc/rfc8301#section-3.1) prohibits SHA-1 for DKIM. This documentation guidance does not change the library's supported algorithms or defaults.

## Publish an RSA domain key

Generate a 2048-bit RSA key and convert the private key for the file/stream constructors:

```shell
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out dkim-private.pem
openssl pkcs8 -topk8 -nocrypt -in dkim-private.pem -outform DER -out dkim-private.der
openssl pkey -in dkim-private.pem -pubout -out dkim-public.pem
```

The 2048-bit size follows [RFC 8301](https://www.rfc-editor.org/rfc/rfc8301#section-3.2). Keep the private key private. Only the public key belongs in DNS.

For signing domain `example.com` and selector `mail`, create a TXT record at `mail._domainkey.example.com`:

```text
v=DKIM1; k=rsa; p=BASE64_PUBLIC_KEY
```

Replace `BASE64_PUBLIC_KEY` with the content of the public-key PEM, excluding the `BEGIN`/`END` lines and line breaks. If your DNS host splits long TXT values into quoted strings, keep those strings within one TXT record. The record format is specified in [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376#section-3.6.1).

## Domain-key validation and DNS

Before signing, the default domain-key check loads the selector's TXT record and validates its version, service type, identity granularity, and correspondence to the private key. You can perform the same check explicitly:

```java
DomainKey domainKey = DomainKeyUtil.getDomainKey("example.com", "mail");
domainKey.check("sender@example.com", rsaPrivateKey);
```

`DomainKey` and `DomainKeyUtil` are in `org.simplejavamail.utils.mail.dkim`; `rsaPrivateKey` is your loaded `RSAPrivateKey`.

DNS lookups use JNDI and the default DNS provider unless configured otherwise. Since `3.3.0`, a process-wide override is available:

```java
DomainKeyUtil.setDnsProviderUrl("dns://192.0.2.53"); // Replace with your DNS server.
```

Configure this before using the signer. Pass `null` to restore the default provider. `DomainKeyUtil.getDnsProviderUrl()` reports the current override.

If your application deliberately manages domain-key validation separately, `signer.setCheckDomainKey(false)` disables the automatic check. Signing is still performed, but the library will no longer confirm that DNS matches the signing key.

## Building and contributing

Use Maven from the repository root. The full verification lane runs on JDK 8:

```shell
mvn verify '-Dmaven.javadoc.skip=true' '-Djacoco.skip=true' '-Dlicense.skip=true'
```

For a JDK 21 runtime check, add `-Dspotbugs.skip=true`; the inherited analyzer does not support that JDK. Full static analysis still runs in the JDK 8 lane. See [compatibility and verification](docs/COMPATIBILITY.md) for the preserved contracts and deferred behavioral changes.

For a focused test run:

```shell
mvn -Dtest=DkimMessageTest test
```

Tests cover canonicalization, domain-key parsing and validation, signer configuration, and serialized signed messages. Golden fixtures protect established message bytes; additional signature checks validate results independently. Test keys are fixtures only. See [AGENTS.md](AGENTS.md) for compatibility and contribution conventions and [MAINTAINER_WORKFLOW.md](MAINTAINER_WORKFLOW.md) for the release process.

The implementation keeps three responsibilities separate: `DkimMessage` integrates with MIME serialization; `DkimSigner` owns signing configuration and signature assembly; `DomainKey` and `DomainKeyUtil` validate and retrieve public keys. Internal helpers handle cryptographic operations, canonicalization, and DNS details. Public API classes remain in `org.simplejavamail.utils.mail.dkim`.

Report reproducible problems through [GitHub issues](https://github.com/simple-java-mail/java-utils-mail-dkim/issues), including the library and Java versions, canonicalization settings, and a sanitized message example when relevant. Preserve exact message bytes when investigating a signature mismatch.

## Origins and license

Maintained by [Simple Java Mail](https://github.com/simple-java-mail). This project continues the archived [markenwerk/java-utils-mail-dkim](https://github.com/markenwerk/java-utils-mail-dkim), which grew from Florian Sager's DKIM for JavaMail project. Original development is credited in the source and project metadata.

Licensed under the [Apache License 2.0](LICENSE-2.0.txt). See [NOTICE](NOTICE).
