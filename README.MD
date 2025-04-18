[![APACHE v2 License](https://img.shields.io/badge/license-apachev2-blue.svg?style=flat)](LICENSE-2.0.txt)
[![Latest Release](https://img.shields.io/maven-central/v/org.simplejavamail/utils-mail-dkim.svg?style=flat)](http://search.maven.org/#search%7Cgav%7C1%7Cg%3A%22org.simplejavamail%22%20AND%20a%3A%22utils-mail-dkim%22)
[![Javadocs](http://www.javadoc.io/badge/org.simplejavamail/utils-mail-dkim.svg)](http://www.javadoc.io/doc/org.simplejavamail/utils-mail-dkim)
[![Codacy](https://img.shields.io/codacy/grade/9f9cd8b379534172bd52565122f794d7?style=flat)](https://www.codacy.com/gh/simple-java-mail/java-utils-mail-dkim)

# org.simplejavamail:utils-mail-dkim

This is a simple to use library to use [DKIM](https://en.wikipedia.org/wiki/DKIM) features in conjunction with [Jakarta Mail](https://eclipse-ee4j.github.io/mail).

Note: This is a revival / continuation of the archived project markenwerk/java-utils-mail-dkim, which itself was a continuation of an abandoned project on SourceForge.

```xml
<dependency>
	<groupId>org.simplejavamail</groupId>
	<artifactId>utils-mail-dkim</artifactId>
	<version>3.2.2</version>
</dependency>
```

## Change history

v3.2.0 - v3.2.2

- 3.2.2: 18-04-2025: update bcpkix-jdk18on dependency to version 1.78.1
- 3.2.1: 13-04-2025: [#8](https://github.com/simple-java-mail/java-utils-mail-dkim/pull/8) resolve vulnerability by migrating from net.i2p.crypto.eddsa to org.bouncycastle.bcpkix-jdk18on
    - resolves [#7](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/7) CVE-2020-36843 Vulnerability
- 3.2.0: 04-05-2024: Bumped angus-mail from 2.0.2 to 2.0.3
- 3.2.0: 04-05-2024: Upgraded release pipeline
- 3.2.0: 04-05-2024: Updated parent pom, which upgraded to Junit 5


v3.1.0 - v3.1.1

- 3.1.1: 04-05-2024: Bumped jakarta.mail-api version from 2.1.2 to 2.1.3
- 3.1.0: 17-01-2024: [#4](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/4) Update to latest Jakarta+Angus dependencies


v3.0.0 (28-12-2021)

- Initial release under the new home of Simple Java Mail, with Jakarta Mail 2.0.1 and CircleCI release pipeline
- Resolved a few minor Spotbugs errors

# Original documenation follows:

## Overview

This library allows you to

 - sign MIME Messages according to the DKIM standard,
 - check, whether the DNS resource record for a sending domain is prepared correctly for DKIM.

Consult the [usage description](#usage) and [Javadoc](http://markenwerk.github.io/java-utils-mail-dkim/index.html) for further information.


## Origin and state

The initial version of this library is based on a project called [DKIM for JavaMail](http://www.agitos.de/dkim-for-javamail/), which allows to sign MIME Messages according to the DKIM standard and fetch the corresponding DNS resource record.
This library extended the DNS resource record check  and integrated it in the signing procedure (this is enabled by default, but can be turned off). In addition to retrieving the corresponding DNS resource record for a signing domain and a selector, the check now tests the following, before signing a MIME message:

 - Check, whether the retrieved public key fits to the given private key.
 - Check, whether the retrieved DKIM granularity fits to the given DKIM identity.
 - Check, whether the retrieved DKIM version is `DKIM1`.
 - Check, whether the retrieved DKIM service type includes `email`.

### Setup

In order to use DKIM, it is necessary to create a RSA key pair and publish the public key in an appropriate DNS entry.

A RSA private pair with a key size of 1024 bits can be generated as a PEM encoded PKCS8 file like this:

```shell
openssl genrsa -out dkim.pem 1024
```

While DKIM should be compatible with any reasonable key size, it might not be possible to publish arbitrary large public keys. See [section 3.3.3.](https://tools.ietf.org/html/rfc6376#section-3.3.3) of the RFC for further information on key sizes. 

Javas standard API only allows to import PKCS8 files in unencrypted PEM encoding. Therefore, it is either necessary to use a third party library like the Java version of [The Legion of the Bouncy Castle](http://www.bouncycastle.org/java.html) or to convert the PEM encoded file into an unencrypted DER encoded file like this:

```shell
openssl pkcs8 -topk8 -nocrypt -in dkim.pem -outform der -out dkim.der
```

The corresponding public key can be obtained from the private key like this:

```shell
openssl rsa -in dkim.pem -pubout
```

This yields an output like this:

```shell
writing RSA key
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCf4lvVllV2eoDqxartI0bUiJXD
v+TVhFoGcheKocQyLGrTi8BKamhoDt8yKiecpCm1rZ/nRyxSqIAJFMV3y/XslSVV
2Sc48efPtrdViGUcGYNCC/KrqYNgCF7vRO2oAQ7ePPBohwcR1hzavGeY/AVxpEeI
vixQNmunxkdaqHCLuQIDAQAB
-----END PUBLIC KEY-----
```

The content of the DNS resource record consists of a set of keys and values, where a typical DNS resource record has values for following keys:

 - `v`: The DKIM version, currently `DKIM1`.
 - `g`: The DKIM granularity, used to restrict the allowed sender identities, usualy `*`. 
 - `k`: The key type, usualy `rsa`.
 - `p`: The Base64 encoded public key, usualy a RSA public key.
 - `s`: The allowed service types, usualy `email` or `*`. 
 - `t`: Some flags used by DKIM validators.
 
See [section 3.6.1.](https://tools.ietf.org/html/rfc6376#section-3.6.1) of the RFC for further information

To publish such a public key, i.e. for the domain `example.com` and the selector `foo`, it is necessary to create a DNS resource record  with type `TXT` for the domain `foo._domainkey.example.com` with the following content:

```
v=DKIM1;g=*;k=rsa;p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCf4lvV
llV2eoDqxartI0bUiJXDv+TVhFoGcheKocQyLGrTi8BKamhoDt8yKiecpCm1rZ/n
RyxSqIAJFMV3y/XslSVV2Sc48efPtrdViGUcGYNCC/KrqYNgCF7vRO2oAQ7ePPBo
hwcR1hzavGeY/AVxpEeIvixQNmunxkdaqHCLuQIDAQAB;s=email;t=s
```

### Helpful tools

You can use [http://dkimcore.org/tools/dkimrecordcheck.html](http://dkimcore.org/tools/dkimrecordcheck.html) to examine the DNS resource record for a given domain and a given selector and [http://dkimvalidator.com/](http://dkimvalidator.com/) to verify, that correct DKIM signatures are generated. 

## Usage

We will assume that you already know how to create a SMTP [`Session`][Session] and how create and send a MIME Message with JavaMail, but here is a minimal example how one could send a simple message:

```java
public void sendMail(Session session, String from, String to, String subject, String content) throws Exception {
	MimeMessage message = new MimeMessage(session);
	message.setFrom(new InternetAddress(from));
	message.setRecipient(RecipientType.TO, new InternetAddress(to));
	message.setSubject(subject);
	message.setContent(content, "text/plain; charset=utf-8");
	MimeMessage dkimSignedMessage = dkimSignMessage(message, from, "example.com", "foo");
	Transport.send(dkimSignedMessage);
}
```

To sign [`MimeMessage`][MimeMessage] with DKIM, you have to configure a [`DkimSigner`][DkimSigner], which can be used multiple times, and create a new [`DkimMessage`][DkimMessage] from the original [`MimeMessage`][MimeMessage] and the [`DkimSigner`][DkimSigner].

```java
private MimeMessage dkimSignMessage(MimeMessage message, String from, String signingDomain, String selector)  throws Exception {
	DkimSigner dkimSigner = new DkimSigner(signingDomain, selector, getDkimPrivateKeyFileForSender(from));
	dkimSigner.setIdentity(from);
	dkimSigner.setHeaderCanonicalization(Canonicalization.SIMPLE);
	dkimSigner.setBodyCanonicalization(Canonicalization.RELAXED);
	dkimSigner.setSigningAlgorithm(SigningAlgorithm.SHA256_WITH_RSA);
	dkimSigner.setLengthParam(true);
	dkimSigner.setCopyHeaderFields(false);
	return new DkimMessage(message, dkimSigner);
}
```

When the message is signed, a check is performed to check, whether the DNS resource record for the given domain and the given selector is prepared correctly for DKIM, i.e. if the given identity matches the configured granularity and if the given private key matches the configured public key. A [`DkimAcceptanceException`][DkimAcceptanceException] is thrown otherwise. *Please be aware, that this happens during `Transport.send(dkimSignedMessage)`.*

To disable this check, which is not recommended, call `dkimSigner.setCheckDomainKey(false)`. Using the [`DomainKeyUtil`][DomainKeyUtil], you can perform this check manually like this:

```java
DomainKey domainKey = DomainKeyUtil.getDomainKey(signingDomain, selector);
domainKey.check(from, getDkimPrivateKeyFileForSender(from));
```