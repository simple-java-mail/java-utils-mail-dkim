package org.simplejavamail.utils.mail.dkim;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MailDateFormat;
import java.text.ParsePosition;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import static java.nio.charset.StandardCharsets.ISO_8859_1;

/**
 * Signs a complete, finalized RFC 5322 message without an Angus message wrapper.
 * Configure an immutable instance with {@link #builder()}; each call owns its cryptographic state.
 * The caller keeps its private key and input bytes stable during signing. No transport is created,
 * no key is destroyed, and no cryptographic provider is installed in the JVM registry.
 */
public final class DkimByteSigner {
    private static final Pattern DOMAIN = Pattern.compile("(.+)\\.(.+)");
    private final DkimSigningEngine.Settings settings;

    private DkimByteSigner(DkimSigningEngine.Settings settings) { this.settings = settings.copy(); }

    /** Returns a new configuration builder with the legacy library's signing defaults. */
    public static Builder builder() { return new Builder(); }

    /**
     * Prepends a DKIM signature to the supplied finalized message, retaining every original byte.
     * Header and body canonicalization affect signing input only. The input must already contain
     * its final encodings, headers and CRLF header/body separator; this method does not construct MIME.
     * DNS checking, when enabled, happens here. The returned array is independent of the input and
     * of every other result. Concurrent calls are supported; concurrent mutation of input/key is not.
     * @param finalizedMessage complete finalized RFC 5322 message, never null
     * @return a new signed message array
     * @throws DkimSigningException if required headers, DNS/key checks or signing fail
     */
    public byte[] sign(byte[] finalizedMessage) throws DkimSigningException {
        ByteInput input = new ByteInput(Objects.requireNonNull(finalizedMessage, "finalizedMessage").clone());
        String header;
        try {
            header = DkimSigningEngine.sign(input, settings, false);
        } catch (DkimSigningException e) {
            throw e;
        } catch (MessagingException e) {
            throw new DkimSigningException("Could not sign the finalized message", e);
        }
        byte[] prefix = (header + "\r\n").getBytes(ISO_8859_1);
        byte[] result = new byte[prefix.length + input.bytes.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(input.bytes, 0, result, prefix.length, input.bytes.length);
        return result;
    }

    /** Collects choices without DNS or content access; {@link #build()} validates the complete configuration. */
    public static final class Builder {
        private final DkimSigningEngine.Settings settings = new DkimSigningEngine.Settings();
        private Builder() { }
        /**
         * Signing domain. Required at construction; its spelling is retained.
         * @param value the supplied choice
         * @return this builder
         */
        public Builder signingDomain(String value) { settings.signingDomain = Objects.requireNonNull(value, "signingDomain"); return this; }
        /**
         * @return the stored choice, without construction or validation
         * @see #signingDomain(String)
         */
        public String getSigningDomain() { return settings.signingDomain; }

        /**
         * DNS selector. Required at construction; its spelling is retained.
         * @param value the supplied choice
         * @return this builder
         */
        public Builder selector(String value) { settings.selector = Objects.requireNonNull(value, "selector"); return this; }
        /**
         * @return the stored choice, without construction or validation
         * @see #selector(String)
         */
        public String getSelector() { return settings.selector; }

        /**
         * Application-owned RSA or Ed25519 private key. It must match the selected algorithm; no ownership or destruction is transferred.
         * @param value the supplied choice
         * @return this builder
         */
        public Builder privateKey(PrivateKey value) { settings.privateKey = Objects.requireNonNull(value, "privateKey"); return this; }
        /**
         * @return the stored choice, without construction or validation
         * @see #privateKey(PrivateKey)
         */
        public PrivateKey getPrivateKey() { return settings.privateKey; }

        /**
         * Signing algorithm, defaulting to SHA256_WITH_RSA. Select SHA256_WITH_ED25519 explicitly for an Ed25519 key. SHA1_WITH_RSA remains available for compatibility.
         * @param value the supplied choice
         * @return this builder
         */
        public Builder signingAlgorithm(SigningAlgorithm value) { settings.signingAlgorithm = Objects.requireNonNull(value, "signingAlgorithm"); return this; }
        /**
         * @return the stored choice, without construction or validation
         * @see #signingAlgorithm(SigningAlgorithm)
         */
        public SigningAlgorithm getSigningAlgorithm() { return settings.signingAlgorithm; }

        /**
         * Restores the documented fallback.
         * @return this builder
         * @see #signingAlgorithm(SigningAlgorithm)
         */
        public Builder resetSigningAlgorithm() { settings.signingAlgorithm = SigningAlgorithm.SHA256_WITH_RSA; return this; }

        /**
         * Header canonicalization, defaulting to RELAXED. Raw field spelling and folding are retained for SIMPLE.
         * @param value the supplied choice
         * @return this builder
         */
        public Builder headerCanonicalization(Canonicalization value) { settings.headerCanonicalization = Objects.requireNonNull(value, "headerCanonicalization"); return this; }
        /**
         * @return the stored choice, without construction or validation
         * @see #headerCanonicalization(Canonicalization)
         */
        public Canonicalization getHeaderCanonicalization() { return settings.headerCanonicalization; }

        /**
         * Restores the documented fallback.
         * @return this builder
         * @see #headerCanonicalization(Canonicalization)
         */
        public Builder resetHeaderCanonicalization() { settings.headerCanonicalization = Canonicalization.RELAXED; return this; }

        /**
         * Body canonicalization, defaulting to SIMPLE. This choice never rewrites the emitted input bytes.
         * @param value the supplied choice
         * @return this builder
         */
        public Builder bodyCanonicalization(Canonicalization value) { settings.bodyCanonicalization = Objects.requireNonNull(value, "bodyCanonicalization"); return this; }
        /**
         * @return the stored choice, without construction or validation
         * @see #bodyCanonicalization(Canonicalization)
         */
        public Canonicalization getBodyCanonicalization() { return settings.bodyCanonicalization; }

        /**
         * Restores the documented fallback.
         * @return this builder
         * @see #bodyCanonicalization(Canonicalization)
         */
        public Builder resetBodyCanonicalization() { settings.bodyCanonicalization = Canonicalization.SIMPLE; return this; }

        /**
         * Optional i= identity; null omits the tag. Its domain must equal or be a subdomain of the signing domain, ignoring domain capitalization. Local-part spelling remains intact.
         * @param value the supplied choice
         * @return this builder
         */
        public Builder identity(String value) { settings.identity = value; return this; }
        /**
         * @return the stored choice, without construction or validation
         * @see #identity(String)
         */
        public String getIdentity() { return settings.identity; }

        /**
         * Restores the documented fallback.
         * @return this builder
         * @see #identity(String)
         */
        public Builder clearIdentity() { settings.identity = null; return this; }

        /**
         * Whether to include the canonical body octet count in l=, default false. This leaves content appended after that length unsigned.
         * @param value the supplied choice
         * @return this builder
         */
        public Builder lengthParam(boolean value) { settings.lengthParam = value; return this; }
        /**
         * @return the stored choice, without construction or validation
         * @see #lengthParam(boolean)
         */
        public boolean getLengthParam() { return settings.lengthParam; }

        /**
         * Restores the documented fallback.
         * @return this builder
         * @see #lengthParam(boolean)
         */
        public Builder resetLengthParam() { settings.lengthParam = false; return this; }

        /**
         * Whether to include copied signed header fields in z=, default false.
         * @param value the supplied choice
         * @return this builder
         */
        public Builder copyHeaderFields(boolean value) { settings.copyHeaderFields = value; return this; }
        /**
         * @return the stored choice, without construction or validation
         * @see #copyHeaderFields(boolean)
         */
        public boolean isCopyHeaderFields() { return settings.copyHeaderFields; }

        /**
         * Restores the documented fallback.
         * @return this builder
         * @see #copyHeaderFields(boolean)
         */
        public Builder resetCopyHeaderFields() { settings.copyHeaderFields = false; return this; }

        /**
         * Whether to check the DNS domain key while signing, default true. False disables the DNS/key check, without omitting the signature.
         * @param value the supplied choice
         * @return this builder
         */
        public Builder checkDomainKey(boolean value) { settings.checkDomainKey = value; return this; }
        /**
         * @return the stored choice, without construction or validation
         * @see #checkDomainKey(boolean)
         */
        public boolean isCheckDomainKey() { return settings.checkDomainKey; }

        /**
         * Restores the documented fallback.
         * @return this builder
         * @see #checkDomainKey(boolean)
         */
        public Builder resetCheckDomainKey() { settings.checkDomainKey = true; return this; }
        /**
         * Adds a nonempty signed-header name, matching case insensitively.
         * @param name header name
         * @return this builder
         */
        public Builder addHeaderToSign(String name) {
            if (name != null && !name.isEmpty()) { settings.headersToSign.add(name); }
            return this;
        }
        /**
         * Removes a signed-header name except mandatory From.
         * @param name header name
         * @return this builder
         */
        public Builder removeHeaderToSign(String name) {
            if (name != null && !"From".equalsIgnoreCase(name)) { settings.headersToSign.remove(name); }
            return this;
        }
        /**
         * Returns a detached set of configured names.
         * @return signed header names
         * @see #addHeaderToSign(String)
         */
        public Set<String> getHeadersToSign() {
            Set<String> result = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
            result.addAll(settings.headersToSign);
            return result;
        }
        /**
         * Restores the default signed-header set.
         * @return this builder
         * @see #addHeaderToSign(String)
         */
        public Builder resetHeadersToSign() {
            settings.headersToSign.clear();
            settings.headersToSign.addAll(DkimSigningEngine.defaultHeaders());
            return this;
        }
        /**
         * Validates the complete configuration and creates an independent immutable signer.
         * No DNS lookup or message read is performed. A failed build leaves the stored choices intact.
         * @return the completed signer
         * @throws DkimException for incomplete/invalid configuration or an incompatible key/algorithm
         */
        public DkimByteSigner build() {
            if (settings.signingDomain == null || !DOMAIN.matcher(settings.signingDomain).matches()) {
                throw new DkimException(settings.signingDomain + " is an invalid signing domain");
            }
            if (settings.selector == null || settings.privateKey == null) {
                throw new DkimException("A selector and private key are required");
            }
            if (settings.identity != null && !endsWithIgnoreCase(settings.identity, "@" + settings.signingDomain)
                    && !endsWithIgnoreCase(settings.identity, "." + settings.signingDomain)) {
                throw new DkimException("The domain part of " + settings.identity + " isn't " + settings.signingDomain + " or a subdomain thereof");
            }
            DkimSigningEngine.Settings completed = settings.copy();
            completed.keyPairType = completed.signingAlgorithm == SigningAlgorithm.SHA256_WITH_ED25519
                    ? KeyPairType.ED25519 : KeyPairType.RSA;
            new SigningOperation(completed.keyPairType, completed.signingAlgorithm, completed.privateKey, false);
            return new DkimByteSigner(completed);
        }
    }

    private static boolean endsWithIgnoreCase(String value, String suffix) {
        return value.regionMatches(true, value.length() - suffix.length(), suffix, 0, suffix.length());
    }

    private static final class ByteInput implements DkimSigningEngine.Input {
        private final byte[] bytes;
        private final List<String> headers = new ArrayList<String>();
        private final int bodyOffset;

        ByteInput(byte[] bytes) throws DkimSigningException {
            this.bytes = bytes;
            int separator = -1;
            for (int i = 0; i <= bytes.length - 4; i++) {
                if (bytes[i] == '\r' && bytes[i + 1] == '\n' && bytes[i + 2] == '\r' && bytes[i + 3] == '\n') {
                    separator = i;
                    break;
                }
            }
            if (separator < 0) { throw new DkimSigningException("Finalized MIME message has no header/body separator"); }
            bodyOffset = separator + 4;
            for (String line : new String(bytes, 0, separator, ISO_8859_1).split("\r\n", -1)) {
                if ((line.startsWith(" ") || line.startsWith("\t")) && !headers.isEmpty()) {
                    int last = headers.size() - 1;
                    headers.set(last, headers.get(last) + "\r\n" + line);
                } else {
                    if (line.indexOf(':') <= 0) { throw new DkimSigningException("Malformed finalized message header"); }
                    headers.add(line);
                }
            }
        }

        public Enumeration<String> getSigningHeaderLines() { return Collections.enumeration(headers); }
        public byte[] getEncodedBodyBytes() { return Arrays.copyOfRange(bytes, bodyOffset, bytes.length); }
        public Date getSentDate() {
            for (String line : headers) {
                int colon = line.indexOf(':');
                if ("Date".equalsIgnoreCase(line.substring(0, colon).trim())) {
                    return new MailDateFormat().parse(line.substring(colon + 1).trim(), new ParsePosition(0));
                }
            }
            return null;
        }
    }
}
