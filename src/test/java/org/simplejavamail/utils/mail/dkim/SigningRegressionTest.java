package org.simplejavamail.utils.mail.dkim;

import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigningRegressionTest {

   private static RSAPrivateCrtKey rsaKey;
   private static PublicKey rsaPublicKey;
   private static KeyPair ed25519;

   @BeforeAll
   static void keys() throws Exception {
      KeyFactory factory = KeyFactory.getInstance("RSA");
      rsaKey = (RSAPrivateCrtKey) factory.generatePrivate(new PKCS8EncodedKeySpec(
            Files.readAllBytes(new File("src/test/resources/key/dkim.der").toPath())));
      rsaPublicKey = factory.generatePublic(new RSAPublicKeySpec(rsaKey.getModulus(), rsaKey.getPublicExponent()));
      Security.addProvider(new BouncyCastleProvider());
      ed25519 = KeyPairGenerator.getInstance("Ed25519", "BC").generateKeyPair();
   }

   static Stream<Object[]> signingConfigurations() {
      List<Object[]> cases = new ArrayList<Object[]>();
      for (SigningAlgorithm algorithm : SigningAlgorithm.values()) {
         for (Canonicalization header : Canonicalization.values()) {
            for (Canonicalization body : Canonicalization.values()) {
               for (String encoding : Arrays.asList("8bit", "quoted-printable", "base64")) {
                  cases.add(new Object[] { algorithm, header, body, encoding });
               }
            }
         }
      }
      return cases.stream();
   }

   @ParameterizedTest(name = "{0}, {1}/{2}, {3}")
   @MethodSource("signingConfigurations")
   void verifiesUnicodeMessagesAndOctetLengths(SigningAlgorithm algorithm, Canonicalization header,
         Canonicalization body, String encoding) throws Exception {
      DkimSigner signer = signer(algorithm);
      signer.setHeaderCanonicalization(header);
      signer.setBodyCanonicalization(body);
      signer.setLengthParam(true);
      MimeMessage message = message("Caf\u00e9 \u20ac \u65e5\u672c\u8a9e\r\nA \t B \t\r\n\r\n");
      message.setHeader("Content-Transfer-Encoding", encoding);
      byte[] wire = write(message, signer);
      SignatureAssertions.assertValidSignature(wire, publicKey(algorithm));
   }

   @Test
   void hashesExistingNonUtf8BytesWithoutChangingTheBody() throws Exception {
      byte[] original = raw("From: sender@example.com\r\nContent-Type: text/plain; charset=ISO-8859-1\r\n"
            + "Content-Transfer-Encoding: 8bit\r\n\r\nCaf\u00e9\r\n");
      MimeMessage message = parsed(original);
      DkimSigner signer = signer(SigningAlgorithm.SHA256_WITH_RSA);
      signer.setLengthParam(true);
      byte[] wire = write(message, signer);
      assertArrayEquals(body(original), body(wire));
      SignatureAssertions.assertValidSignature(wire, rsaPublicKey);
   }

   @Test
   void simpleHeadersPreserveSpacingFoldingAndDuplicateOrder() throws Exception {
      MimeMessage message = parsed(raw("From:sender@example.com\r\nSubject:\tA folded\r\n\tsubject\r\n"
            + "X-Trace:first\r\nX-Trace:  second\r\nContent-Transfer-Encoding: 7bit\r\n\r\nHello\r\n"));
      DkimSigner signer = signer(SigningAlgorithm.SHA256_WITH_RSA);
      signer.setHeaderCanonicalization(Canonicalization.SIMPLE);
      signer.addHeaderToSign("x-trace");
      byte[] wire = write(message, signer);
      String text = new String(wire, ISO_8859_1);
      assertTrue(text.contains("From:sender@example.com\r\n"));
      assertTrue(text.contains("Subject:\tA folded\r\n\tsubject\r\n"));
      SignatureAssertions.assertValidSignature(wire, rsaPublicKey);
   }

   @Test
   void selectsHeadersWithWhitespaceBeforeTheColon() throws Exception {
      MimeMessage message = parsed(raw("From \t:sender@example.com\r\nSubject \t: spaced\r\n\r\nHello\r\n"));
      SignatureAssertions.assertValidSignature(write(message, signer(SigningAlgorithm.SHA256_WITH_RSA)), rsaPublicKey);
   }

   @Test
   void excludedHeadersAreNotSignedAndDoNotAffectLaterWrites() throws Exception {
      DkimMessage message = new DkimMessage(message("Hello\r\n"), signer(SigningAlgorithm.SHA256_WITH_RSA));
      ByteArrayOutputStream filtered = new ByteArrayOutputStream();
      message.writeTo(filtered, new String[] { "Subject" });
      assertFalse(new String(filtered.toByteArray(), ISO_8859_1).contains("Subject:"));
      SignatureAssertions.assertValidSignature(filtered.toByteArray(), rsaPublicKey);
      ByteArrayOutputStream complete = new ByteArrayOutputStream();
      message.writeTo(complete);
      assertTrue(new String(complete.toByteArray(), ISO_8859_1).contains("Subject:"));
      SignatureAssertions.assertValidSignature(complete.toByteArray(), rsaPublicKey);
   }

   @Test
   void cannotExcludeTheMandatoryFromHeader() throws Exception {
      DkimMessage message = new DkimMessage(message("Hello\r\n"), signer(SigningAlgorithm.SHA256_WITH_RSA));
      assertThrows(DkimSigningException.class, () -> message.writeTo(new ByteArrayOutputStream(), new String[] { "From" }));
   }

   @Test
   void verifiesMultipartAttachments() throws Exception {
      MimeMessage message = message("unused");
      MimeMultipart multipart = new MimeMultipart();
      MimeBodyPart text = new MimeBodyPart();
      text.setText("Caf\u00e9\r\n", "UTF-8");
      multipart.addBodyPart(text);
      MimeBodyPart attachment = new MimeBodyPart();
      attachment.setContent("attachment contents\r\n", "text/plain; charset=US-ASCII");
      attachment.setFileName("example.txt");
      multipart.addBodyPart(attachment);
      message.setContent(multipart);
      SignatureAssertions.assertValidSignature(write(message, signer(SigningAlgorithm.SHA256_WITH_RSA)), rsaPublicKey);
   }

   @Test
   void sharedSignerProducesIndependentValidSignatures() throws Exception {
      final DkimSigner signer = signer(SigningAlgorithm.SHA256_WITH_RSA);
      ExecutorService executor = Executors.newFixedThreadPool(8);
      final CountDownLatch start = new CountDownLatch(1);
      try {
         List<Callable<byte[]>> tasks = new ArrayList<Callable<byte[]>>();
         for (int index = 0; index < 64; index++) {
            final int number = index;
            tasks.add(() -> {
               assertTrue(start.await(10, TimeUnit.SECONDS));
               return write(message("Message " + number + "\r\n"), signer);
            });
         }
         List<Future<byte[]>> results = new ArrayList<Future<byte[]>>();
         for (Callable<byte[]> task : tasks) {
            results.add(executor.submit(task));
         }
         start.countDown();
         for (Future<byte[]> result : results) {
            SignatureAssertions.assertValidSignature(result.get(30, TimeUnit.SECONDS), rsaPublicKey);
         }
      } finally {
         executor.shutdownNow();
         assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS));
      }
   }

   @Test
   void retryAfterOutputFailureRetainsValidSignature() throws Exception {
      DkimMessage message = new DkimMessage(message("Hello\r\n"), signer(SigningAlgorithm.SHA256_WITH_RSA));
      assertThrows(IOException.class, () -> message.writeTo(new OutputStream() {
         @Override public void write(int value) throws IOException { throw new IOException("test output failure"); }
      }));
      ByteArrayOutputStream retry = new ByteArrayOutputStream();
      message.writeTo(retry);
      SignatureAssertions.assertValidSignature(retry.toByteArray(), rsaPublicKey);
   }

   @Test
   void verifierDetectsBodyAndHeaderTampering() throws Exception {
      byte[] wire = write(message("Original body\r\n"), signer(SigningAlgorithm.SHA256_WITH_RSA));
      SignatureAssertions.assertValidSignature(wire, rsaPublicKey);
      String text = new String(wire, ISO_8859_1);
      assertThrows(AssertionError.class, () -> SignatureAssertions.assertValidSignature(
            text.replace("Original body", "Modified body").getBytes(ISO_8859_1), rsaPublicKey));
      assertThrows(AssertionError.class, () -> SignatureAssertions.assertValidSignature(
            text.replace("Subject: Test subject", "Subject: Modified subject").getBytes(ISO_8859_1), rsaPublicKey));
   }

   @Test
   void defaultsAndFailedAlgorithmChangesRemainCompatible() throws Exception {
      DkimSigner signer = new DkimSigner("example.com", "selector", rsaKey);
      assertEquals(SigningAlgorithm.SHA256_WITH_RSA, signer.getSigningAlgorithm());
      assertEquals(Canonicalization.RELAXED, signer.getHeaderCanonicalization());
      assertEquals(Canonicalization.SIMPLE, signer.getBodyCanonicalization());
      assertTrue(signer.isCheckDomainKey());
      assertFalse(signer.getLengthParam());
      assertFalse(signer.isCopyHeaderFields());
      assertThrows(DkimException.class, () -> signer.setSigningAlgorithm(SigningAlgorithm.SHA256_WITH_ED25519));
      assertEquals(SigningAlgorithm.SHA256_WITH_RSA, signer.getSigningAlgorithm());
      signer.setCheckDomainKey(false);
      signer.removeHeaderToSign("fRoM");
      SignatureAssertions.assertValidSignature(write(message("Hello\r\n"), signer), rsaPublicKey);
   }

   @Test
   void identityAndCopiedHeadersKeepTheirExistingOptions() throws Exception {
      DkimSigner signer = signer(SigningAlgorithm.SHA256_WITH_RSA);
      signer.setIdentity("a=;b@example.com");
      signer.setCopyHeaderFields(true);
      MimeMessage message = message("Hello\r\n");
      message.setSubject("A | B; C= D");
      byte[] wire = write(message, signer);
      String text = new String(wire, ISO_8859_1);
      assertTrue(text.contains("i=a=3D=3Bb@example.com;"));
      assertTrue(text.contains("=7C"));
      assertTrue(text.contains("=3B"));
      SignatureAssertions.assertValidSignature(wire, rsaPublicKey);
      assertThrows(DkimException.class, () -> signer.setIdentity("sender@other.example"));
      signer.setIdentity("sender@sub.example.com");
      assertEquals("sender@sub.example.com", signer.getIdentity());
      signer.setIdentity(null);
      assertEquals(null, signer.getIdentity());
   }

   @SuppressWarnings("deprecation")
   @Test
   void legacyZAliasesAndHeaderCustomizationRemainAvailable() throws Exception {
      DkimSigner signer = signer(SigningAlgorithm.SHA256_WITH_RSA);
      signer.setZParam(true);
      assertTrue(signer.isZParam());
      assertTrue(signer.isCopyHeaderFields());
      signer.setZParam(false);
      signer.addHeaderToSign("X-Custom");
      signer.addHeaderToSign(null);
      signer.addHeaderToSign("");
      signer.removeHeaderToSign("Subject");
      signer.removeHeaderToSign(null);
      signer.removeHeaderToSign("");
      MimeMessage message = message("Hello\r\n");
      message.setHeader("X-Custom", "custom value");
      String text = new String(write(message, signer), ISO_8859_1);
      assertTrue(text.contains("h=X-Custom:"));
      assertFalse(text.substring(0, text.indexOf("\r\n\r\n")).contains(":Subject:"));
      SignatureAssertions.assertValidSignature(text.getBytes(ISO_8859_1), rsaPublicKey);
      assertThrows(DkimException.class, () -> signer.setSigningAlgorithm(null));
   }

   @Test
   void copiedLongHeadersUseDkimEncodingWithoutMimeSoftBreaks() throws Exception {
      DkimSigner signer = signer(SigningAlgorithm.SHA256_WITH_RSA);
      signer.setCopyHeaderFields(true);
      MimeMessage message = message("Hello\r\n");
      char[] subject = new char[180];
      Arrays.fill(subject, 'a');
      message.setSubject(new String(subject));
      byte[] wire = write(message, signer);
      String headers = new String(wire, ISO_8859_1).split("\r\n\r\n", 2)[0];
      Matcher copiedHeaders = Pattern.compile("(?s);\\s*z=(.*?);").matcher(headers);
      assertTrue(copiedHeaders.find());
      assertFalse(copiedHeaders.group(1).contains("=\r\n"), "DKIM tag values cannot contain MIME quoted-printable soft breaks");
      SignatureAssertions.assertValidSignature(wire, rsaPublicKey);
   }

   @Test
   void protocolTokensIgnoreDefaultLocale() throws Exception {
      Locale previous = Locale.getDefault();
      try {
         Locale.setDefault(Locale.forLanguageTag("tr-TR"));
         assertEquals("simple", Canonicalization.SIMPLE.getType());
         assertEquals("mime-version:1.0", Canonicalization.RELAXED.canonicalizeHeader("MIME-Version", "1.0"));
         DkimSigner signer = signer(SigningAlgorithm.SHA256_WITH_RSA);
         signer.setHeaderCanonicalization(Canonicalization.SIMPLE);
         SignatureAssertions.assertValidSignature(write(message("Hello\r\n"), signer), rsaPublicKey);
      } finally {
         Locale.setDefault(previous);
      }
   }

   @Test
   void constructorClosesDerStreamAndPreservesValidation() throws Exception {
      final boolean[] closed = { false };
      ByteArrayInputStream stream = new ByteArrayInputStream(rsaKey.getEncoded()) {
         @Override public void close() throws IOException { closed[0] = true; super.close(); }
      };
      new DkimSigner("example.com", "selector", stream);
      assertTrue(closed[0]);
      assertThrows(DkimException.class, () -> new DkimSigner("invalid", "selector", rsaKey));
      assertThrows(DkimException.class, () -> new DkimSigner(null, "selector", rsaKey));
   }

   @Test
   void preservesProtectedBodyExtensionPoint() throws Exception {
      DkimMessage message = new DkimMessage(message("Hello\r\n"), signer(SigningAlgorithm.SHA256_WITH_RSA)) {
         @Override protected String getEncodedBody() { return new String(super.getEncodedBody().getBytes(UTF_8), UTF_8); }
      };
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      message.writeTo(output);
      SignatureAssertions.assertValidSignature(output.toByteArray(), rsaPublicKey);
      message.setAllow8bitMIME(true);
      assertFalse(message.getAllow8bitMIME());
   }

   private static DkimSigner signer(SigningAlgorithm algorithm) throws Exception {
      DkimSigner signer = algorithm == SigningAlgorithm.SHA256_WITH_ED25519
            ? new DkimSigner("example.com", "selector", (EdDSAPrivateKey) ed25519.getPrivate())
            : new DkimSigner("example.com", "selector", rsaKey);
      signer.setSigningAlgorithm(algorithm);
      signer.setCheckDomainKey(false);
      return signer;
   }

   private static PublicKey publicKey(SigningAlgorithm algorithm) {
      return algorithm == SigningAlgorithm.SHA256_WITH_ED25519 ? ed25519.getPublic() : rsaPublicKey;
   }

   private static MimeMessage message(String body) throws Exception {
      Properties properties = new Properties();
      properties.setProperty("mail.from", "sender@example.com");
      MimeMessage message = new MimeMessage(Session.getInstance(properties));
      message.setFrom("sender@example.com");
      message.setRecipients(MimeMessage.RecipientType.TO, "recipient@example.net");
      message.setSubject("Test subject");
      message.setSentDate(new Date(0));
      message.setText(body, "UTF-8");
      return message;
   }

   private static MimeMessage parsed(byte[] bytes) throws MessagingException {
      return new MimeMessage(Session.getInstance(new Properties()), new ByteArrayInputStream(bytes));
   }

   private static byte[] write(MimeMessage message, DkimSigner signer) throws Exception {
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      new DkimMessage(message, signer).writeTo(output);
      return output.toByteArray();
   }

   private static byte[] raw(String value) {
      return value.getBytes(ISO_8859_1);
   }

   private static byte[] body(byte[] wire) {
      int separator = new String(wire, ISO_8859_1).indexOf("\r\n\r\n");
      return Arrays.copyOfRange(wire, separator + 4, wire.length);
   }
}
