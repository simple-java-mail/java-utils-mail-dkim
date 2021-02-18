package net.markenwerk.utils.mail.dkim;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import org.junit.Test;

public class DomainKeyTest {

   private static final String EXAMPLE_DOMAIN_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB";

   /**
    * Test a valid record using the example public key from RFC 6376 appendix C
    */
   @Test
   public void checkDomainKeyRecognizesPublicKey() throws Exception {

      Map<Character, String> tags = new HashMap<Character, String>();
      tags.put('v', "DKIM1");
      tags.put('p', EXAMPLE_DOMAIN_KEY);

      DomainKey domainKey = new DomainKey(tags);

      assertNotNull(domainKey);
      assertArrayEquals(Base64.getDecoder().decode(EXAMPLE_DOMAIN_KEY), domainKey.getPublicKey().getEncoded());

   }

   @Test
   public void checkHashWithEmptyBody() throws Exception {

      checkBodyHash("", "empty body");

   }

   private void checkBodyHash(String body, String description) throws Exception {

		for (Canonicalization canonicalization : Canonicalization.values()) {
			for (SigningAlgorithm algorithm : new SigningAlgorithm[] {SigningAlgorithm.SHA1_WITH_RSA, SigningAlgorithm.SHA256_WITH_RSA}) {
				checkBodyHash(canonicalization, algorithm, body, description);
			}
		}
	}

   private void checkBodyHash(Canonicalization canonicalization, SigningAlgorithm algorithm, String body,
         String description) throws Exception {

      String configuration = canonicalization.name() + " " + algorithm.getHashNotation().toUpperCase();
      String expected = Utils.digest(canonicalization.canonicalizeBody(body), algorithm.getHashNotation());
      String actual = calculateBodyHashWithSigner(Utils.getSigner(canonicalization, algorithm));

      assertEquals(configuration + " / " + description, expected, actual);

   }

   private String calculateBodyHashWithSigner(DkimSigner dkimSigner) throws Exception {

      Properties properties = new Properties();
      properties.setProperty("mail.smtp.host", "localhost");

      Session session = Session.getInstance(properties);

      MimeMessage mimeMessage = new MimeMessage(session);
      mimeMessage.setRecipient(Message.RecipientType.TO, new InternetAddress("test@exapmle.com"));
      mimeMessage.setSubject("Title");
      mimeMessage.setFrom("support@example.com");
      mimeMessage.setText("", "US-ASCII", "plain");
      mimeMessage.setHeader("Content-Transfer-Encoding", "7bit");
      mimeMessage.setHeader("Content-Type", "text/plain; charset=\"US-ASCII\"");
      mimeMessage.saveChanges();

      DkimMessage dkimMessage = new DkimMessage(mimeMessage, dkimSigner);
      dkimMessage.writeTo(new ByteArrayOutputStream());

      String signature = dkimSigner.sign(dkimMessage);

      Pattern pattern = Pattern.compile("bh=(.+?);", Pattern.MULTILINE);
      Matcher matcher = pattern.matcher(signature);

      if (!matcher.find()) {
         return "";
      }

      return matcher.group(1);
   }
}
