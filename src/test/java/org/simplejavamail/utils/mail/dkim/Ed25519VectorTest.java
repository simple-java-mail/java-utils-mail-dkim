package org.simplejavamail.utils.mail.dkim;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class Ed25519VectorTest {

   // RFC 8463 appendix A: public example keys and independently published signature.
   private static final String SIGNATURE = "/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus"
         + "Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==";

   private static final String DKIM = "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;\r\n"
         + " d=football.example.com; i=@football.example.com;\r\n"
         + " q=dns/txt; s=brisbane; t=1528637909; h=from : to :\r\n"
         + " subject : date : message-id : from : subject : date;\r\n"
         + " bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n b=";

   @Test
   void matchesPublishedHeaderSignature() throws Exception {
      Security.addProvider(new BouncyCastleProvider());
      PrivateKey privateKey = KeyFactory.getInstance("Ed25519", "BC").generatePrivate(new PKCS8EncodedKeySpec(
            prefixed(new byte[] {0x30, 0x2e, 0x02, 0x01, 0, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20},
                  "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=")));
      String canonicalHeaders = "from:Joe SixPack <joe@football.example.com>\r\n"
            + "to:Suzie Q <suzie@shopping.example.net>\r\n"
            + "subject:Is dinner ready?\r\n"
            + "date:Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n"
            + "message-id:<20030712040037.46341.5F8J@football.example.com>\r\n"
            + "dkim-signature:v=1; a=ed25519-sha256; c=relaxed/relaxed; "
            + "d=football.example.com; i=@football.example.com; "
            + "q=dns/txt; s=brisbane; t=1528637909; h=from : to : "
            + "subject : date : message-id : from : subject : date; "
            + "bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=";
      SigningOperation operation = new SigningOperation(KeyPairType.ED25519, SigningAlgorithm.SHA256_WITH_ED25519, privateKey);
      assertArrayEquals(Base64.getDecoder().decode(SIGNATURE), operation.sign(canonicalHeaders.getBytes(US_ASCII)));
   }

   @Test
   void independentVerifierAcceptsPublishedMessage() throws Exception {
      PublicKey publicKey = KeyFactory.getInstance("Ed25519", new BouncyCastleProvider()).generatePublic(new X509EncodedKeySpec(
            prefixed(new byte[] {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0},
                  "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")));
      String message = DKIM + SIGNATURE + "\r\n"
            + "From: Joe SixPack <joe@football.example.com>\r\n"
            + "To: Suzie Q <suzie@shopping.example.net>\r\n"
            + "Subject: Is dinner ready?\r\n"
            + "Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n"
            + "Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n\r\n"
            + "Hi.\r\n\r\nWe lost the game.  Are you hungry yet?\r\n\r\nJoe.\r\n\r\n";
      SignatureAssertions.assertValidSignature(message.getBytes(US_ASCII), publicKey);
   }

   private static byte[] prefixed(byte[] prefix, String base64) {
      byte[] key = Base64.getDecoder().decode(base64);
      byte[] encoded = new byte[prefix.length + key.length];
      System.arraycopy(prefix, 0, encoded, 0, prefix.length);
      System.arraycopy(key, 0, encoded, prefix.length, key.length);
      return encoded;
   }
}
