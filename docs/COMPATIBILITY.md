# Patch compatibility and verification

The current maintenance work repairs existing functionality without requiring
callers to change their code or configuration. It does not publish a release;
the POM and README dependency example remain at `3.3.0`.

## Preserved contracts

- Public and protected constructors and methods, enum constants, and package
  names remain available. No new application API is required.
- Java 8 source and bytecode compatibility, dependency versions, and automatic
  module name `org.simplejavamail.utils.mail.dkim` remain unchanged.
- RSA-SHA256 remains the default for RSA keys. The existing Ed25519 constructor
  still selects Ed25519-SHA256. SHA-1 remains available for compatibility.
- Header canonicalization remains relaxed and body canonicalization remains
  simple. Domain-key checks remain enabled. Identity, body length (`l=`), and
  copied header fields (`z=`) remain omitted unless configured.
- The default signed-header set and mandatory `From` header remain unchanged.
- Established golden signed-message contents are retained. Git treats test
  resources as binary so intentional LF, CRLF, and mixed endings survive checkout;
  Surefire starts test JVMs in UTC before Jakarta Mail caches its date formatter.
  Reverse alphabetical test order initializes MIME handling before the golden
  tests, retaining a regression control for initialization order.
- MIME body bytes are preserved when a message is serialized. Configure a signer
  before sharing it; concurrent reconfiguration and concurrent writes of the same
  message are not new supported contracts.

## Intentional bug-fix differences

Incorrect signatures necessarily change when corrected. The affected cases are
listed in [Unreleased](../CHANGELOG.md#unreleased): non-UTF-8 MIME bytes and `l=`
counts, raw headers under simple canonicalization, omitted output headers,
locale-sensitive protocol tokens, shared cryptographic state, Ed25519 signing,
and long copied header fields. Existing caller code uses the same APIs.

For Ed25519, the existing constructor now uses the bundled Bouncy Castle
provider and the RFC-defined SHA-256 header prehash. DNS decoding accepts the
standard raw key format while retaining legacy encoded-key support. Malformed
truncated keys produce `DkimException` rather than leaking a provider exception.
An Ed448 key incorrectly declared as Ed25519 is rejected during decoding rather
than being mislabeled and failing later during the signing-key check
([#27](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/27)).

DNS fixes close resources, remove the global lock from network access, expire
old cache entries, and keep stale lookups from repopulating the cache after a
provider change. Valid whitespace, folded key values, and extension tags are
handled without imposing a new duplicate-record or duplicate-tag policy.

## Deliberately deferred changes

The following need a separate compatibility decision:

- **Serialized line endings:** [#25](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/25)
  tracks normalizing raw LF body output to CRLF. That would change transmitted
  message bytes and existing golden output; this patch preserves them.
- **Public relaxed-header semantics:** [#26](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/26)
  tracks narrowing control-whitespace handling in the public canonicalization
  method. Locale-independent lowercasing is fixed, while the existing whitespace
  behavior remains.
- **Validation and signing policy:** rejecting duplicate tags or multiple TXT
  records more strictly, removing SHA-1, enforcing a different key strength,
  changing signing defaults, and replacing existing constructors with broader
  key/provider APIs are outside this patch scope.
- **Inherited analysis tooling:** [#24](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/24)
  tracks the old SpotBugs version's JDK 21 incompatibility. Upgrading the parent
  or analyzer is separate dependency maintenance.

## Verification lanes

Run full verification on JDK 8:

```shell
mvn verify '-Dmaven.javadoc.skip=true' '-Djacoco.skip=true' '-Dlicense.skip=true'
```

Run the suite on JDK 21 while retaining the project's Java 8 compilation target:

```shell
mvn verify '-Dmaven.javadoc.skip=true' '-Djacoco.skip=true' '-Dlicense.skip=true' '-Dspotbugs.skip=true'
```

The second command checks compilation, tests, and packaging on the modern JDK;
it does not replace the first lane's static analysis. Regression coverage combines
unchanged golden messages, independent cryptographic verification, RFC Ed25519
vectors, MIME/encoding cases, concurrent signing, and deterministic DNS fixtures.

For an optional coverage report on JDK 21, attach JaCoCo to the test JVM while
keeping the inherited offline instrumentation disabled:

```powershell
mvn dependency:copy '-Dartifact=org.jacoco:org.jacoco.agent:0.8.12:jar:runtime' '-DoutputDirectory=target/coverage'
Remove-Item -LiteralPath target/jacoco.exec -ErrorAction SilentlyContinue
mvn verify '-Dmaven.javadoc.skip=true' '-Djacoco.skip=true' '-Dlicense.skip=true' '-Dspotbugs.skip=true' '-DargLine=-javaagent:target/coverage/org.jacoco.agent-0.8.12-runtime.jar=destfile=target/jacoco.exec'
mvn org.jacoco:jacoco-maven-plugin:0.8.12:report '-Djacoco.skip=false'
```

The HTML report is written to `target/site/jacoco/index.html`. Instrumentation
occurs in the test JVM; packaged library classes remain free of JaCoCo probes.

After packaging, run the baseline compatibility probe:

```powershell
.\scripts\verify-compatibility.ps1 -BaselineJar '<published 3.3.0 JAR>' -Java8Home '<JDK 8>' -ModernJavaHome '<JDK 21>'
```

It compares public/protected declarations and compiles a consumer against the
published baseline on JDK 8. Those unchanged classes then run with the baseline
and candidate on both JDKs, with deterministic message output compared. The
probe also recompiles the consumer against the candidate on each JDK. This
checks a concrete existing-client path in addition to the regression suite;
it does not claim to exercise every possible downstream application.

See [MAINTAINER_WORKFLOW.md](../MAINTAINER_WORKFLOW.md) for release authorization,
CircleCI gates, and publication checks.
