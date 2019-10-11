package net.markenwerk.utils.mail.dkim;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Test;

import javax.mail.Header;
import javax.mail.Message;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

public class DomainKeyTest {

	/**
	 * Test a valid record using the example public key from the DKIM spec page
	 * http://dkim.org/specs/rfc4871-dkimbase.html
	 */
	@Test
	public void happyCase() {
		Map<Character, String> tags = new HashMap<Character, String>();
		tags.put('v', "DKIM1");
		tags.put('p',
				"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB");

		DomainKey dk = new DomainKey(tags);
		assertNotNull(dk);
	}

	@Test
	public void checkHashWithEmptyBody() throws Exception {
		// SIMPLE
		// The SHA-1 value (in base64) for an empty body (canonicalized to a "CRLF") is: uoq1oCgLlTqpdDX/iUbLy7J1Wic=
		assertEquals("SIMPLE SHA-1 with empty body", "uoq1oCgLlTqpdDX/iUbLy7J1Wic=",
				calculateBodyHash(mkSigner(Canonicalization.SIMPLE, SigningAlgorithm.SHA1_WITH_RSA)));

		// The SHA-256 value is: frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=
		assertEquals("SIMPLE SHA-256 with empty body", "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=",
				calculateBodyHash(mkSigner(Canonicalization.SIMPLE, SigningAlgorithm.SHA256_WITH_RSA)));

		// RELAXED
		// The SHA-1 value (in base64) for an empty body (canonicalized to a null input) is: 2jmj7l5rSw0yVb/vlWAYkK/YBwk=
		assertEquals("RELAXED SHA-1 with empty body", "2jmj7l5rSw0yVb/vlWAYkK/YBwk=",
				calculateBodyHash(mkSigner(Canonicalization.RELAXED, SigningAlgorithm.SHA1_WITH_RSA)));

		// The SHA-256 value is: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
		assertEquals("RELAXED SHA-256 with empty body", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
				calculateBodyHash(mkSigner(Canonicalization.RELAXED, SigningAlgorithm.SHA256_WITH_RSA)));
	}

	private DkimSigner mkSigner(Canonicalization canonicalization, SigningAlgorithm algorithm) throws Exception {
		// signer
		DkimSigner signer = new DkimSigner("example.com", "dkim1", new File("private_key.pk8"));
		signer.setHeaderCanonicalization(canonicalization);
		signer.setBodyCanonicalization(canonicalization);
		signer.setLengthParam(true);
		signer.setSigningAlgorithm(algorithm);
		signer.setZParam(false);
		signer.setCheckDomainKey(false);

		return signer;
	}

	private String calculateBodyHash(DkimSigner signer) throws Exception {
		// Session
		Properties properties=new Properties();
		properties.setProperty("mail.smtp.host", "localhost");
		Session session=Session.getDefaultInstance(properties);
		// Message
		MimeMessage message = new MimeMessage(session);
		message.setRecipient(Message.RecipientType.TO, new InternetAddress("test@exapmle.com"));
		message.setSubject("Title");
		message.setFrom("support@example.com");
		message.setText("", "US-ASCII", "plain");
		message.setHeader("Content-Transfer-Encoding", "7bit");
		message.setHeader("Content-Type", "text/plain; charset=\"US-ASCII\"");
		message.saveChanges();
		DkimMessage dkimMessage = new DkimMessage(message, signer);
		dkimMessage.writeTo(new ByteArrayOutputStream());

		Pattern pattern = Pattern.compile("bh=(.+?);", Pattern.MULTILINE);
		Matcher m = pattern.matcher(signer.sign(dkimMessage));

		if(!m.find()) {
			return "";
		}
		return m.group(1);
	}
}
