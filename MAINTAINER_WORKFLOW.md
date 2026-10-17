# Maintainer Workflow

This document describes the normal maintenance and release workflow for
`simple-java-mail/java-utils-mail-dkim` (`org.simplejavamail:utils-mail-dkim`).
The repository uses a single long-lived `master` branch, Maven, and CircleCI.

Repository facts:

- GitHub: `simple-java-mail/java-utils-mail-dkim`
- Maven: `org.simplejavamail:utils-mail-dkim`
- Source and bytecode baseline: Java 8
- Automatic module name: `org.simplejavamail.utils.mail.dkim`
- Developer landing page: `README.MD` (retain the filename's case)
- Release history: `CHANGELOG.md` and the tag-specific GitHub release
- Release automation: `.circleci/config.yml`, using the `github-maven-deploy` orb

This follows the same maintenance model as `generic-object-pool`, adapted to
DKIM message-byte compatibility and this repository's single published JAR.

## 1. Interpret the request

Decide whether the request is issue triage, implementation without a release,
release preparation, or an explicitly authorized release. Never infer release
authorization from words such as "patch" when they only describe a code diff.
An explicit request to publish a patch, minor, major, or as-is version remains
authorization through the corresponding CircleCI approval and GitHub release.

Do not create tags or change the POM version by hand during ordinary release
preparation. The CircleCI release jobs own version changes, deployment, and tags.

## 2. Start from live state

```powershell
git status --short --branch
git fetch --prune --tags origin
git branch -vv
gh auth status
```

Understand and preserve unrelated local changes before starting. Create a
short-lived implementation branch from current `origin/master` and target
`master` for review. Do not discard local work to obtain a clean checkout; use
an isolated worktree when needed. Release automation still runs from `master`.
Never rewrite shared history to resolve divergence.

The supported source and bytecode baseline is Java 8. Verify the effective
toolchain before implementation or release work:

```powershell
java -version
mvn -version
mvn -q help:evaluate '-Dexpression=maven.compiler.source' -DforceStdout
```

## 3. Triage issues and pull requests

Read the live issue or pull request, comments, labels, milestone, and linked
commits before editing. Re-read labels immediately before changing them.

Use the repository's canonical labels. Added functionality uses either
`enhancement` or `major feature`, never both. Other work types are `bug`,
`maintenance`, `documentation`, `security`, `dependencies`, and
`3rdparty-problem`. Priority labels are `Priority-Low`, `Priority-Medium`, and
`Priority-High`. Workflow and disposition labels include `duplicate`, `invalid`,
`question`, `need-user-input`, `needs-research`, `postponed indefinitely`,
`will close soon`, `wontfix`, and `help wanted`; `java` identifies Java update
pull requests.

Preserve genuinely distinct project labels. When replacing an alias, migrate its
issues and pull requests to the canonical label before deleting or renaming it.
Remove stale workflow labels when their state is no longer true.

Issue titles describe the outcome directly. Do not prefix new titles with
`Bug:`, `Feature:`, `[maintenance]`, or similar type markers; labels carry type.

## 4. Release milestones

Every semantic-version tag has one milestone whose title is the exact numeric
version without a `v` prefix. Its description is empty, its due date is the
actual historical release date at UTC midnight, and it is closed after every
member is closed.

Assign every issue and merged pull request represented by a release to that
version's milestone. Do not include rejected, superseded, or unrelated work.
GitHub exposes pull requests through the issues endpoint for milestone updates.

```powershell
gh api 'repos/simple-java-mail/java-utils-mail-dkim/milestones?state=all&per_page=100' --paginate
gh api --method PATCH repos/simple-java-mail/java-utils-mail-dkim/issues/NUMBER -F milestone=MILESTONE_NUMBER
```

When creating or repairing historical milestones, derive the date from the
release notes or annotated tag date. PATCH `due_on` explicitly after creation or
closure and verify the raw API value is exactly `YYYY-MM-DDT00:00:00Z`.

## 5. Implement and verify

Read the affected implementation and tests first. Treat generated message bytes,
header ordering, CRLF handling, canonicalization, DNS lookups, signing defaults,
and exception behavior as compatibility-sensitive. Do not casually regenerate
golden signed-message fixtures or change `setCheckDomainKey(true)` behavior.

For patch work, keep public and protected signatures, enum constants, defaults,
Java compatibility, and existing working output stable. A bug fix may correct
previously invalid signatures; identify the affected input and explain that
output change in the unreleased notes. Stop and discuss changes that require
caller migration or alter a valid existing policy, such as disabling SHA-1,
changing key-strength enforcement, or tightening ambiguous DNS-record handling.

Keep configuration and orchestration in the existing public facade classes;
extract implementation details into package-private helpers when that separates
MIME serialization, canonicalization, cryptography, and DNS access. Do not add
public abstractions merely to reorganize internal code.

Add regression coverage for each demonstrated defect. Check signatures with an
independent verifier as well as golden output. Include parsed messages, MIME
encodings, both canonicalizations and supported algorithms, repeated/concurrent
use, and failure paths where relevant. Use controlled DNS fixtures rather than
live Internet records. Coordinate concurrency tests with synchronization rather
than timing-only sleeps. Restore any JVM-wide state changed by tests, such as
timezone, locale, or JNDI configuration.

Run focused tests first, then the full verification on JDK 8, using the same
command shape as CircleCI:

```powershell
mvn -Dtest=DkimMessageTest test
mvn verify '-Dmaven.javadoc.skip=true' '-Djacoco.skip=true' '-Dlicense.skip=true'
```

Surefire starts each test JVM in UTC before Jakarta Mail initializes its cached
date formatter. The default reverse alphabetical test order initializes MIME
handling before the golden-message tests. Preserve the startup timezone when
supplying an optional `argLine`, such as a coverage agent. To check an explicitly
non-UTC Maven invocation with that order:

```powershell
mvn test '-Duser.timezone=Europe/Amsterdam' '-Dsurefire.runOrder=reversealphabetical' '-Djacoco.skip=true' '-Dlicense.skip=true'
```

The inherited OSS Index `audit-dependencies` execution is unbound from the
Maven lifecycle in this project. Normal verification and release builds do not
invoke that remote vulnerability scan.

Run the same suite on JDK 21 with the inherited SpotBugs analyzer skipped:

```powershell
mvn verify '-Dmaven.javadoc.skip=true' '-Djacoco.skip=true' '-Dlicense.skip=true' '-Dspotbugs.skip=true'
```

The existing analyzer cannot process JDK 21 classes; this is tracked in
[#24](https://github.com/simple-java-mail/java-utils-mail-dkim/issues/24).
Do not describe that lane as full static-analysis verification. Retain the
JDK 8 run with SpotBugs enabled. See [compatibility boundaries](docs/COMPATIBILITY.md)
for the fixed and deliberately deferred behavior.

After packaging, run the compatibility probe with the published `3.3.0` JAR
and both installed JDKs:

```powershell
.\scripts\verify-compatibility.ps1 -BaselineJar '<published 3.3.0 JAR>' -Java8Home '<JDK 8>' -ModernJavaHome '<JDK 21>'
```

The probe compares public/protected declarations, runs a consumer compiled
against the baseline unchanged with both JARs on both JDKs, checks deterministic
message output, and recompiles the consumer against the candidate. Supply
`-CandidateJar` to override the packaged JAR or `-DependencyClasspathFile` to
use an existing dependency classpath instead of resolving one with Maven.

Before committing, inspect both the unstaged and staged diff. Do not mix
unrelated dependency, formatting, documentation, or release-note changes.

## 6. Documentation and repository release notes

`README.MD` is the developer landing page. Keep its dependency example, Java
baseline, automatic module name, existing-API examples, and signing defaults
accurate. Keep the version shown there aligned with the published artifact;
ordinary implementation work does not advance it.

`CHANGELOG.md` retains the release history. Add concise user-visible changes
under `Unreleased`, distinguishing compatibility fixes from new features.
When a release is authorized, finalize that section for the exact released
version and update the README dependency example after the release version is
known. Preserve historical notes rather than duplicating the archive in the
front page.

Release notes should emphasize behavior users can observe. Skip internal build
details unless they affect published artifacts. A patch can be concise, but its
GitHub release body must still stand alone.

## 7. Commit and push

Stage selectively and use a semantic subject:

```powershell
git add <paths>
git diff --cached --check
git diff --cached --stat
git commit -m "fix(scope): concise summary"
```

Use semantic subjects and do not add a sign-off unless explicitly requested.
Push the implementation branch or open a pull request when requested. Do not
infer permission to push, publish, or contact issue participants merely from a
request for local fixes. Direct `master` pushes are reserved for authorized
maintainer work; never force-push `master`.

Use `[skip ci]` for bookkeeping-only documentation when appropriate. Do not use
it for code, dependency, build, or release-lane changes that require validation.

## 8. Release through CircleCI

Release only with explicit authorization. Push the fully verified candidate to
`master`, then approve exactly one CircleCI gate:

- `approve-deploy-patch-version`
- `approve-deploy-minor-version`
- `approve-deploy-major-version`
- `approve-deploy-as-is-version`

The deployment publishes to Maven Central and creates the release commit and
numeric tag. If Maven Central publication succeeds but repository updates fail,
confirm that immutable external state before repairing the version commit or tag.
Never create a second Central deployment for the same version.

CircleCI currently filters `build-and-test` to `master`; a topic-branch push
alone does not provide that build. Run the full local verification before
review and wait for the successful `master` build before release approval.
The deploy command skips tests, so the earlier verification is required.

After deployment, fetch `master` and tags, verify the Maven Central artifact,
and confirm the local branch can be fast-forwarded to `origin/master`. Inspect a
published JAR when signing output, JPMS metadata, or JaCoCo packaging changed.

## 9. GitHub releases

Every semantic-version tag has exactly one published, non-prerelease GitHub
release. Keep the numeric tag unchanged and title the release `vVERSION`.
Preserve assets already attached to a release.

Each body must be a permanent, tag-specific record that:

- states what changed in that version;
- links useful issues, pull requests, or exact commits;
- explains source, binary, runtime, module-path, or dependency compatibility;
- does not delegate essential meaning to mutable branch documentation; and
- omits test evidence and internal release-process commentary.

Create one release even for a no-functional-change tag; say explicitly that API,
dependencies, and behavior are unchanged. Never fold several tags into one
GitHub release.

## 10. Historical bookkeeping

For an existing tag, reconstruct facts from the tag range, changelog history,
issues, and pull requests. Create a retrospective issue only for a coherent,
substantive bug, security fix, feature, or user-visible enhancement that lacks a
record. Its body must link exact commit evidence and identify the first release.
Apply canonical labels and the actual release milestone, close it, and avoid
duplicating an existing issue or pull request. Do not invent issues for version
bumps, formatting, routine build work, or ordinary dependency updates.

Historical GitHub releases may be published today, but their milestones retain
the original release dates.

## 11. Definition of done

For implementation without a release:

- Requested changes and regression coverage are committed on the intended branch.
- Required tests pass, or any omission is explained.
- The diff contains only intentional changes and the worktree is clean.
- `README.MD` and `CHANGELOG.md` describe the final behavior accurately, with
  development changes under `Unreleased` and published coordinates unchanged.
- Compatibility-sensitive changes and any deferred behavioral decisions are
  reported to the maintainer.
- Pushes, pull requests, and external metadata updates are completed only when
  included in the authorized task.

For a release, additionally:

- The Maven Central artifact and POM are available for the released version.
- `master`, `origin/master`, and the numeric tag agree; the checkout is clean.
- Relevant issues and merged pull requests have canonical labels and the actual
  release milestone.
- The released tag has a closed, dated, empty-description milestone and exactly
  one published, self-contained GitHub release.
- `README.MD` coordinates and compatibility guidance and `CHANGELOG.md` history
  agree with the published artifacts.
