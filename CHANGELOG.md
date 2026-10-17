# Changelog

## 3.3.1 (17 October 2026)

- Existing public and protected APIs, signing defaults, Java 8 compatibility, and dependency versions remain unchanged. Callers need no migration. Previously incorrect signatures change for the affected inputs; see [compatibility boundaries](docs/COMPATIBILITY.md).
- Correct MIME body hashing and optional `l=` byte counts for non-UTF-8 8-bit content, preserve raw header whitespace under simple canonicalization, and exclude headers omitted by `writeTo(...)` from the signature ([#14](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/14), [#15](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/15), [#16](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/16)). The transmitted body bytes are preserved.
- Repair the existing Ed25519 signing path and DNS public-key decoding for RFC 8463 interoperability. Truncated keys and incompatible Ed448 encodings declared as Ed25519 now fail with `DkimException` during key decoding ([#17](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/17), [#22](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/22), [#27](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/27)).
- Make protocol output independent of the JVM's default locale and isolate cryptographic state for concurrent use of a configured signer ([#12](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/12), [#13](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/13)).
- Close DNS resources reliably, avoid holding the global configuration lock during network lookups, and correct cache expiration and DNS-provider configuration races ([#18](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/18), [#19](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/19), [#20](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/20)).
- Accept valid whitespace and folded public-key values in DNS records without letting extension tags overwrite known tags ([#21](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/21)).
- Encode long copied header fields (`z=`) using legal DKIM folding rather than MIME quoted-printable soft breaks ([#23](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/23)).

## 3.3.0 (5 July 2026)

- Added `DomainKeyUtil.setDnsProviderUrl(...)` and `DomainKeyUtil.getDnsProviderUrl()` to configure the JNDI DNS provider used for DKIM domain-key TXT lookups, resolving [#3](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/3).
- Fixed the published `Automatic-Module-Name` to `org.simplejavamail.utils.mail.dkim`, closing [#9](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/9) and incorporating [#5](https://github.com/simple-java-mail/java-utils-mail-dkim/pull/5).
- Kept packaged JARs free of JaCoCo offline instrumentation, resolving [#6](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/6).
- Migrated release publishing from legacy OSSRH staging to the Maven Central Portal, with CircleCI configured to auto-publish Central deployments.
- No breaking API changes: existing DNS lookup behavior remains the default unless a DNS provider URL is configured.

## 3.2.0–3.2.2

- 3.2.2 (18 April 2025): updated `bcpkix-jdk18on` to 1.78.1.
- 3.2.1 (13 April 2025): [#8](https://github.com/simple-java-mail/java-utils-mail-dkim/pull/8) migrated from `net.i2p.crypto.eddsa` to `org.bouncycastle:bcpkix-jdk18on`, resolving [#7](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/7), CVE-2020-36843.
- 3.2.0 (4 May 2024): updated Angus Mail from 2.0.2 to 2.0.3, upgraded the release pipeline, and updated the parent POM, moving tests to JUnit 5.

## 3.1.0–3.1.1

- 3.1.1 (4 May 2024): updated Jakarta Mail API from 2.1.2 to 2.1.3.
- 3.1.0 (17 January 2024): [#4](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/4) updated Jakarta Mail and Angus dependencies.

## 3.0.0 (28 December 2021)

- Initial release under Simple Java Mail, with Jakarta Mail 2.0.1 and a CircleCI release pipeline.
- Resolved minor SpotBugs findings.
