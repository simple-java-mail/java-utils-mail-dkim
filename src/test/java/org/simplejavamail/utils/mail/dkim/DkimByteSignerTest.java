package org.simplejavamail.utils.mail.dkim;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static org.junit.jupiter.api.Assertions.*;

class DkimByteSignerTest {
    private static PrivateKey rsa;
    private static PublicKey rsaPublic;
    private static KeyPair ed;

    @BeforeAll
    static void keys() throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKey key = (RSAPrivateCrtKey) factory.generatePrivate(new PKCS8EncodedKeySpec(
                Files.readAllBytes(new File("src/test/resources/key/dkim.der").toPath())));
        rsa = key;
        rsaPublic = factory.generatePublic(new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent()));
        ed = KeyPairGenerator.getInstance("Ed25519", new BouncyCastleProvider()).generateKeyPair();
    }

    static Stream<Object[]> configurations() {
        List<Object[]> cases = new ArrayList<Object[]>();
        for (SigningAlgorithm algorithm : SigningAlgorithm.values()) {
            for (Canonicalization header : Canonicalization.values()) {
                for (Canonicalization body : Canonicalization.values()) {
                    cases.add(new Object[] {algorithm, header, body});
                }
            }
        }
        return cases.stream();
    }

    @ParameterizedTest
    @MethodSource("configurations")
    void signsExactOctetsAndRepeatedRawHeaders(SigningAlgorithm algorithm, Canonicalization header,
                                               Canonicalization body) throws Exception {
        byte[] input = message("Caf\u00e9 \t\r\nA  B\t\r\n\r\n");
        byte[] before = input.clone();
        DkimByteSigner signer = builder(algorithm).headerCanonicalization(header).bodyCanonicalization(body)
                .lengthParam(true).copyHeaderFields(true).identity("Sender@EXAMPLE.COM").build();
        byte[] output = signer.sign(input);
        assertArrayEquals(before, input);
        assertArrayEquals(input, Arrays.copyOfRange(output, output.length - input.length, output.length));
        SignatureAssertions.assertValidSignature(output, publicKey(algorithm));
        assertArrayEquals(output, signer.sign(input));
        output[0] ^= 1;
        SignatureAssertions.assertValidSignature(signer.sign(input), publicKey(algorithm));
    }

    @Test
    void keepsDefaultsAndBuilderInspectionPassive() {
        DkimByteSigner.Builder builder = DkimByteSigner.builder();
        assertNull(builder.getPrivateKey());
        assertNull(builder.getSigningDomain());
        assertEquals(SigningAlgorithm.SHA256_WITH_RSA, builder.getSigningAlgorithm());
        assertEquals(Canonicalization.RELAXED, builder.getHeaderCanonicalization());
        assertEquals(Canonicalization.SIMPLE, builder.getBodyCanonicalization());
        assertTrue(builder.isCheckDomainKey());
        assertFalse(builder.getLengthParam());
        assertFalse(builder.isCopyHeaderFields());
        assertThrows(DkimException.class, builder::build);
    }

    @Test
    void detachesBuiltSettingsAndHeaderInspection() throws Exception {
        DkimByteSigner.Builder builder = builder(SigningAlgorithm.SHA256_WITH_RSA);
        DkimByteSigner original = builder.build();
        byte[] signed = original.sign(message("body\r\n"));
        builder.getHeadersToSign().clear();
        builder.bodyCanonicalization(Canonicalization.RELAXED).removeHeaderToSign("Subject");
        assertArrayEquals(signed, original.sign(message("body\r\n")));
        assertFalse(Arrays.equals(signed, builder.build().sign(message("body\r\n"))));
        assertThrows(NullPointerException.class, () -> builder.privateKey(null));
        assertSame(rsa, builder.getPrivateKey());
        assertThrows(DkimException.class, () -> builder.identity("Sender@notexample.com").build());
        builder.clearIdentity();
        assertNotNull(builder.build());
    }

    @Test
    void validatesAtConstructionAndMessageBoundaries() {
        assertThrows(DkimException.class, () -> builder(SigningAlgorithm.SHA256_WITH_RSA).privateKey(ed.getPrivate()).build());
        DkimByteSigner signer = builder(SigningAlgorithm.SHA256_WITH_RSA).build();
        assertThrows(DkimSigningException.class, () -> signer.sign("From: x@example.com".getBytes(ISO_8859_1)));
        assertThrows(DkimSigningException.class, () -> signer.sign("Subject: x\r\n\r\nbody".getBytes(ISO_8859_1)));
    }

    @Test
    void retainsNoSharedCryptographicStateAndDoesNotRegisterProviders() throws Exception {
        Provider[] before = Security.getProviders();
        final DkimByteSigner signer = builder(SigningAlgorithm.SHA256_WITH_ED25519).build();
        ExecutorService executor = Executors.newFixedThreadPool(4);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<byte[]>> futures = new ArrayList<Future<byte[]>>();
            for (int i = 0; i < 16; i++) {
                final int value = i;
                futures.add(executor.submit(() -> { start.await(); return signer.sign(message("body " + value + "\r\n")); }));
            }
            start.countDown();
            for (Future<byte[]> future : futures) {
                SignatureAssertions.assertValidSignature(future.get(10, TimeUnit.SECONDS), ed.getPublic());
            }
        } finally {
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS));
        }
        assertArrayEquals(before, Security.getProviders());
    }

    private static DkimByteSigner.Builder builder(SigningAlgorithm algorithm) {
        return DkimByteSigner.builder().signingDomain("example.com").selector("mail")
                .privateKey(algorithm == SigningAlgorithm.SHA256_WITH_ED25519 ? ed.getPrivate() : rsa)
                .signingAlgorithm(algorithm).checkDomainKey(false);
    }

    private static PublicKey publicKey(SigningAlgorithm algorithm) {
        return algorithm == SigningAlgorithm.SHA256_WITH_ED25519 ? ed.getPublic() : rsaPublic;
    }

    private static byte[] message(String body) {
        return ("From: Sender@example.com\r\nSubject:raw subject\r\n\tcontinued\r\nDate: Thu, 1 Jan 1970 00:00:00 +0000\r\n"
                + "Message-ID: <byte-signer@example.com>\r\nReferences: <first@example.com>\r\nReferences: <second@example.com>\r\n"
                + "Content-Type: text/plain; charset=ISO-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + body).getBytes(ISO_8859_1);
    }
}
