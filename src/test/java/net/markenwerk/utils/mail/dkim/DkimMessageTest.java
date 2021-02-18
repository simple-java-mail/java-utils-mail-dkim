package net.markenwerk.utils.mail.dkim;

import static org.junit.Assert.assertArrayEquals;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.Properties;
import java.util.Random;

import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import org.junit.Before;
import org.junit.Test;

public class DkimMessageTest {

	/**
	 * create DKIM messages at certain moment, then store those messages as "valid
	 * message".
	 */
	public static void main(String[] args) throws Exception {
		System.setProperty("user.timezone", "UTC");
		createRandomBodies();
		createSignedMessages();
	}

	private static void createRandomBodies() throws IOException {
		Random random = new Random();
		for (int i = 0; i < 50; i++) {
			int length = random.nextInt(2000) + 100;
			String body = Utils.randomString(random, length);
			Utils.write(new File("./src/test/resources/body", "random" + (i + 1) + ".txt"), body.getBytes());
		}
	}

	private static void createSignedMessages() throws Exception {
		File[] files = new File("./src/test/resources/body").listFiles();
		for (File file : files) {
			String body = new String(Utils.read(file));
			for (Canonicalization canonicalization : Canonicalization.values()) {
				for (SigningAlgorithm algorithm : SigningAlgorithm.values()) {
					createSignedMessage(canonicalization, algorithm, body, file);
				}
			}
		}
	}

	private static void createSignedMessage(Canonicalization canonicalization, SigningAlgorithm algorithm, String body,
			File file) throws Exception {
		String folderName = getFolderName(canonicalization, algorithm);
		byte[] bytes = writeMessage(Utils.getSigner(canonicalization, algorithm), body);
		Utils.write(new File("./src/test/resources/" + folderName, file.getName()), bytes);
	}

	@Before
	public void fixateSystemTimeZone() {
		System.setProperty("user.timezone", "UTC");
	}

	@Test
	public void checkCreatesSameMessageAsBefore() throws Exception {
		File[] files = new File("./src/test/resources/body").listFiles();
		for (File file : files) {
			String body = new String(Utils.read(file));
			for (Canonicalization canonicalization : Canonicalization.values()) {
				for (SigningAlgorithm algorithm : new SigningAlgorithm[] {SigningAlgorithm.SHA1_WITH_RSA, SigningAlgorithm.SHA256_WITH_RSA}) {
					checkCreatesSameMessageAsBefore(canonicalization, algorithm, body, file);
				}
			}
		}
	}

	private void checkCreatesSameMessageAsBefore(Canonicalization canonicalization, SigningAlgorithm algorithm,
			String body, File file) throws Exception {

		String folderName = getFolderName(canonicalization, algorithm);
		byte[] expected = Utils.read(new File("./src/test/resources/" + folderName, file.getName()));
		byte[] actual = writeMessage(Utils.getSigner(canonicalization, algorithm), body);

		String configuration = canonicalization.name() + " " + algorithm.getHashNotation().toUpperCase();
		assertArrayEquals(configuration + " / " + file.getName(), expected, actual);

	}

	private static String getFolderName(Canonicalization canonicalization, SigningAlgorithm algorithm) {
		int index = algorithm.getDkimNotation().indexOf("-") + 1;
		return algorithm.getDkimNotation().substring(index) + "_" + canonicalization.name().toLowerCase();
	}

	private static byte[] writeMessage(DkimSigner dkimSigner, String body) throws Exception {

		Properties properties = new Properties();
		properties.setProperty("mail.smtp.host", "exapmle.com");
		properties.setProperty("mail.from", "foo@exapmle.com");
		properties.setProperty("mail.smtp.from", "exapmle.com");

		Session session = Session.getInstance(properties);

		MimeMessage mimeMessage = new MimeMessage(session) {

			@Override // bind "Message-ID"
			protected void updateMessageID() throws MessagingException {
				super.updateMessageID();
				String messageId = getHeader("Message-ID")[0];
				String address = messageId.substring(1, messageId.length() - 1);
				int index = address.lastIndexOf('@');
				this.setHeader("Message-ID", "<msgid" + address.substring(index) + ">");
			}

		};

		mimeMessage.setSentDate(new Date((long) 1e9));
		mimeMessage.setRecipient(Message.RecipientType.TO, new InternetAddress("test@exapmle.com"));
		mimeMessage.setSubject("Title");
		mimeMessage.setFrom("support@example.com");
		mimeMessage.setText(body, "US-ASCII", "plain");
		mimeMessage.setHeader("Content-Transfer-Encoding", "7bit");
		mimeMessage.setHeader("Content-Type", "text/plain; charset=\"US-ASCII\"");
		mimeMessage.saveChanges();

		DkimMessage dkimMessage = new DkimMessage(mimeMessage, dkimSigner);
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		dkimMessage.writeTo(out);

		return out.toByteArray();

	}

}
