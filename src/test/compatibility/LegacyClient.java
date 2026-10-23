import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.TimeZone;

import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import org.simplejavamail.utils.mail.dkim.Canonicalization;
import org.simplejavamail.utils.mail.dkim.DkimAcceptanceException;
import org.simplejavamail.utils.mail.dkim.DkimException;
import org.simplejavamail.utils.mail.dkim.DkimMessage;
import org.simplejavamail.utils.mail.dkim.DkimSigner;
import org.simplejavamail.utils.mail.dkim.DkimSigningException;
import org.simplejavamail.utils.mail.dkim.DomainKey;
import org.simplejavamail.utils.mail.dkim.DomainKeyUtil;
import org.simplejavamail.utils.mail.dkim.KeyPairType;
import org.simplejavamail.utils.mail.dkim.SigningAlgorithm;

/** Compiled against the baseline, then run unchanged against the candidate. */
@SuppressWarnings("deprecation")
public final class LegacyClient {

    public static void main(String[] args) throws Exception {
        require(args.length == 1, "Expected the test resource directory");
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        File keyFile = new File(args[0], "key/dkim.der");
        byte[] keyBytes = Files.readAllBytes(keyFile.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKey key = (RSAPrivateCrtKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent()));

        checkDefaults(new DkimSigner("example.com", "selector", keyFile));
        ClosingStream stream = new ClosingStream(keyBytes);
        checkDefaults(new DkimSigner("example.com", "selector", stream));
        require(stream.closed, "DER stream ownership");
        checkDomainKey(key, publicKey);
        checkUtilityConfiguration();
        checkExceptionConstructors();

        TrackingSigner signer = new TrackingSigner(key);
        checkDefaults(signer);
        signer.setSigningAlgorithm(SigningAlgorithm.SHA1_WITH_RSA);
        require(signer.getSigningAlgorithm() == SigningAlgorithm.SHA1_WITH_RSA, "RSA SHA-1 setter");
        signer.setSigningAlgorithm(SigningAlgorithm.SHA256_WITH_RSA);
        signer.setHeaderCanonicalization(Canonicalization.SIMPLE);
        signer.setBodyCanonicalization(Canonicalization.RELAXED);
        require(signer.getHeaderCanonicalization() == Canonicalization.SIMPLE, "Header setter");
        require(signer.getBodyCanonicalization() == Canonicalization.RELAXED, "Body setter");
        signer.setHeaderCanonicalization(Canonicalization.RELAXED);
        signer.setBodyCanonicalization(Canonicalization.SIMPLE);
        signer.setIdentity("compat@example.com");
        require("compat@example.com".equals(signer.getIdentity()), "Identity setter");
        signer.setLengthParam(true);
        require(signer.getLengthParam(), "Length setter");
        signer.setZParam(true);
        require(signer.isZParam() && signer.isCopyHeaderFields(), "Legacy z= alias");
        signer.setCopyHeaderFields(false);
        require(!signer.isZParam(), "Legacy z= getter alias");
        signer.addHeaderToSign("X-Compat");
        signer.removeHeaderToSign("x-compat");
        signer.removeHeaderToSign("From");
        signer.setCheckDomainKey(false);
        require(!signer.isCheckDomainKey(), "Domain lookup setter");

        MimeMessage original = new MimeMessage(Session.getInstance(new Properties())) {
            @Override protected void updateMessageID() throws MessagingException {
                setHeader("Message-ID", "<legacy-client@example.com>");
            }
        };
        original.setFrom("compat@example.com");
        original.setRecipients(MimeMessage.RecipientType.TO, "recipient@example.net");
        original.setSubject("Legacy compatibility client");
        original.setSentDate(new Date(1000000000L));
        original.setText("Legacy body\r\n", "US-ASCII");
        original.setHeader("X-Compat", "retained");
        original.saveChanges();
        TrackingMessage message = new TrackingMessage(original, signer);
        message.setAllow8bitMIME(true);
        require(!message.getAllow8bitMIME(), "8-bit MIME remains disabled");
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        message.writeTo(output, new String[] { "Bcc" });
        require(signer.calls == 1, "Protected signer extension");
        require(message.bodyCalls > 0, "Protected encoded-body extension");
        String wire = new String(output.toByteArray(), StandardCharsets.US_ASCII);
        require(wire.startsWith("DKIM-Signature: "), "DKIM header output");
        require(wire.endsWith("\r\n\r\nLegacy body\r\n"), "MIME body output");
        require(wire.contains("From: compat@example.com\r\n"), "Mandatory From remains signed and emitted");
        String checksum = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(output.toByteArray()));
        DkimMessage customBody = new DkimMessage(original, signer) {
            @Override protected String getEncodedBody() { return "hook body\r\n"; }
        };
        ByteArrayOutputStream customOutput = new ByteArrayOutputStream();
        customBody.writeTo(customOutput);
        String expectedHash = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256")
                .digest("hook body\r\n".getBytes(StandardCharsets.US_ASCII)));
        require(new String(customOutput.toByteArray(), StandardCharsets.US_ASCII).contains("bh=" + expectedHash + ";"),
                "Protected body customization affects signing input");
        System.out.println("Legacy compatibility client passed; message SHA-256=" + checksum);
    }

    private static void checkDefaults(DkimSigner signer) {
        require(signer.getSigningAlgorithm() == SigningAlgorithm.SHA256_WITH_RSA, "Default signing algorithm");
        require(signer.getHeaderCanonicalization() == Canonicalization.RELAXED, "Default header canonicalization");
        require(signer.getBodyCanonicalization() == Canonicalization.SIMPLE, "Default body canonicalization");
        require(signer.isCheckDomainKey(), "Default domain-key check");
        require(!signer.getLengthParam() && !signer.isCopyHeaderFields(), "Optional signature parameters");
        require(signer.getIdentity() == null, "Default identity");
        require("rsa-sha256".equals(SigningAlgorithm.SHA256_WITH_RSA.getDkimNotation()), "Algorithm DKIM notation");
        require("SHA256withRSA".equals(SigningAlgorithm.SHA256_WITH_RSA.getJavaNotation()), "Algorithm Java notation");
        require("sha-256".equals(SigningAlgorithm.SHA256_WITH_RSA.getHashNotation()), "Algorithm hash notation");
        require(KeyPairType.RSA.getDefaultSigningAlgorithm() == SigningAlgorithm.SHA256_WITH_RSA, "RSA default");
        require(KeyPairType.RSA.supportsSigningAlgorithm(SigningAlgorithm.SHA1_WITH_RSA), "RSA compatibility algorithm");
        require("rsa".equals(KeyPairType.RSA.getDkimNotation()), "Key DKIM notation");
        require("RSA".equals(KeyPairType.RSA.getJavaNotation()), "Key Java notation");
        require("simple".equals(Canonicalization.SIMPLE.getType()), "Canonicalization type");
        require("Subject: Example".equals(Canonicalization.SIMPLE.canonicalizeHeader("Subject", "Example")), "Simple header API");
        require("subject:Example".equals(Canonicalization.RELAXED.canonicalizeHeader("Subject", " Example ")), "Relaxed header API");
        require("body\r\n".equals(Canonicalization.SIMPLE.canonicalizeBody("body\r\n\r\n")), "Simple body API");
        require("a b\r\n".equals(Canonicalization.RELAXED.canonicalizeBody("a \t b \t\r\n")), "Relaxed body API");
    }

    private static void checkDomainKey(RSAPrivateKey privateKey, PublicKey publicKey) throws Exception {
        Map<Character, String> tags = new HashMap<Character, String>();
        tags.put('p', Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        DomainKey domainKey = new DomainKey(tags);
        require(domainKey.getPublicKeyType() == KeyPairType.RSA, "Domain key default type");
        require(domainKey.getPublicKey().equals(publicKey), "Domain public key");
        require(domainKey.getGranularity().matcher("any-local-part").matches(), "Default granularity");
        require(domainKey.getServiceTypes().contains("*"), "Default service types");
        require(domainKey.getTags().get('p').equals(tags.get('p')), "Domain key tags");
        require(domainKey.getTimestamp() > 0 && domainKey.toString().startsWith("DomainKey ["), "Domain key metadata");
        domainKey.check(null, privateKey);
        domainKey.check("compat@example.com", privateKey);
        tags.put('g', "compat*");
        DomainKey restricted = new DomainKey(tags);
        restricted.check("compat@example.com", privateKey);
        boolean rejected = false;
        try {
            restricted.check("other@example.com", privateKey);
        } catch (DkimAcceptanceException expected) {
            rejected = true;
        }
        require(rejected, "Existing granularity rejection");
    }

    private static void checkUtilityConfiguration() {
        long previousTtl = DomainKeyUtil.getCacheTtl();
        String previousProvider = DomainKeyUtil.getDnsProviderUrl();
        try {
            DomainKeyUtil.setCacheTtl(12345L);
            require(DomainKeyUtil.getCacheTtl() == 12345L, "Cache TTL setter");
            DomainKeyUtil.setCacheTtl(-1);
            require(DomainKeyUtil.getCacheTtl() == 7200000L, "Default cache TTL reset");
            DomainKeyUtil.setDnsProviderUrl(" dns://127.0.0.1 ");
            require("dns://127.0.0.1".equals(DomainKeyUtil.getDnsProviderUrl()), "DNS provider normalization");
            DomainKeyUtil.setDnsProviderUrl(" ");
            require(DomainKeyUtil.getDnsProviderUrl() == null, "Default DNS provider reset");
        } finally {
            DomainKeyUtil.setCacheTtl(previousTtl);
            DomainKeyUtil.setDnsProviderUrl(previousProvider);
        }
    }

    private static void checkExceptionConstructors() {
        Exception cause = new IOException("cause");
        require("message".equals(new DkimException("message").getMessage()), "DkimException constructor");
        require(new DkimException("message", cause).getCause() == cause, "DkimException cause");
        require(new DkimSigningException("message") instanceof MessagingException, "Signing exception hierarchy");
        require(new DkimSigningException("message", cause).getCause() instanceof IOException, "Signing exception cause");
        require(new DkimAcceptanceException("message") instanceof DkimSigningException, "Acceptance exception hierarchy");
        require(new DkimAcceptanceException("message", cause).getCause() instanceof IOException, "Acceptance exception cause");
    }

    private static void require(boolean condition, String description) {
        if (!condition) {
            throw new AssertionError(description);
        }
    }

    private static final class ClosingStream extends ByteArrayInputStream {
        boolean closed;
        ClosingStream(byte[] bytes) { super(bytes); }
        @Override public void close() throws IOException { closed = true; super.close(); }
    }

    private static final class TrackingSigner extends DkimSigner {
        int calls;
        TrackingSigner(RSAPrivateKey key) { super("example.com", "selector", key); }
        @Override protected String sign(DkimMessage message) throws MessagingException {
            calls++;
            return super.sign(message);
        }
    }

    private static final class TrackingMessage extends DkimMessage {
        int bodyCalls;
        TrackingMessage(MimeMessage message, DkimSigner signer) throws MessagingException { super(message, signer); }
        @Override protected String getEncodedBody() {
            bodyCalls++;
            return super.getEncodedBody();
        }
    }
}
