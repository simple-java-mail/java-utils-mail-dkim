package org.simplejavamail.dkim.consumer;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.simplejavamail.utils.mail.dkim.*;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

/** Launch in a fresh JVM with Angus absent and no registered BC provider. */
public final class ByteSigningConsumer {
    private ByteSigningConsumer() { }

    public static void main(String[] args) throws Exception {
        try {
            Class.forName("org.eclipse.angus.mail.smtp.SMTPMessage");
            throw new AssertionError("Angus must be absent from this consumer");
        } catch (ClassNotFoundException expected) { }
        if (Security.getProvider("BC") != null) { throw new AssertionError("Consumer must start without BC registered"); }
        Provider[] providers = Security.getProviders();
        DkimByteSigner.class.getDeclaredMethods();
        DkimByteSigner.class.getDeclaredConstructors();
        DkimByteSigner.builder().getClass().getDeclaredMethods();
        String previousDns = DomainKeyUtil.getDnsProviderUrl();
        long previousTtl = DomainKeyUtil.getCacheTtl();
        try {
            DomainKeyUtil.setCacheTtl(7200000);
            for (SigningAlgorithm algorithm : SigningAlgorithm.values()) {
                boolean ed = algorithm == SigningAlgorithm.SHA256_WITH_ED25519;
                KeyPairGenerator generator = ed ? KeyPairGenerator.getInstance("Ed25519", new BouncyCastleProvider())
                        : KeyPairGenerator.getInstance("RSA");
                if (!ed) { generator.initialize(1024); }
                KeyPair key = generator.generateKeyPair();
                byte[] publicBytes = key.getPublic().getEncoded();
                if (ed) { publicBytes = Arrays.copyOfRange(publicBytes, publicBytes.length - 32, publicBytes.length); }
                String record = "v=DKIM1; k=" + (ed ? "ed25519" : "rsa") + "; g=Sender; p="
                        + Base64.getEncoder().encodeToString(publicBytes);
                try (DnsTxtServer server = new DnsTxtServer(record)) {
                    DomainKeyUtil.setDnsProviderUrl(server.url());
                    for (Canonicalization header : Canonicalization.values()) {
                        for (Canonicalization body : Canonicalization.values()) {
                            DkimByteSigner signer = DkimByteSigner.builder().signingDomain("example.com").selector("mail")
                                    .privateKey(key.getPrivate()).signingAlgorithm(algorithm).identity("Sender@EXAMPLE.COM")
                                    .headerCanonicalization(header).bodyCanonicalization(body).build();
                            byte[] input = ("From: Sender@example.com\r\nSubject:no added space\r\n\tcontinued\r\n"
                                    + "Date: Thu, 1 Jan 1970 00:00:00 +0000\r\nMessage-ID: <neutral@example.com>\r\n"
                                    + "Content-Type: text/plain; charset=ISO-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\nCaf\u00e9\r\n")
                                    .getBytes(StandardCharsets.ISO_8859_1);
                            byte[] signed = signer.sign(input);
                            SignatureAssertions.assertValidSignature(signed, key.getPublic());
                            if (!Arrays.equals(input, Arrays.copyOfRange(signed, signed.length - input.length, signed.length))) {
                                throw new AssertionError("Finalized message bytes changed");
                            }
                            if (!Arrays.equals(signed, signer.sign(input))) { throw new AssertionError("Repeated output changed"); }
                        }
                    }
                    if (server.requestCount() != 1) { throw new AssertionError("Expected one cold lookup and subsequent cache hits"); }
                    if (!Arrays.equals(providers, Security.getProviders())) { throw new AssertionError("Provider registry changed"); }
                }
            }
        } finally {
            DomainKeyUtil.setDnsProviderUrl(previousDns);
            DomainKeyUtil.setCacheTtl(previousTtl);
        }
        System.out.println("Provider-neutral byte signing, DNS and independent signature checks completed.");
    }
}
