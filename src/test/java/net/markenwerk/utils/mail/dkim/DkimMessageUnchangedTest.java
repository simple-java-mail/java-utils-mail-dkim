package net.markenwerk.utils.mail.dkim;

import java.io.*;
import java.util.*;

import javax.mail.*;
import javax.mail.internet.*;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertArrayEquals;

public class DkimMessageUnchangedTest {

    private enum Cannon {
        simple(Canonicalization.SIMPLE),
        relaxed(Canonicalization.RELAXED);

        Canonicalization cannon;
        Cannon(Canonicalization cannon) {
            this.cannon = cannon;
        }
    }

    private enum Algo {
        sha256(SigningAlgorithm.SHA256_WITH_RSA),
        sha1(SigningAlgorithm.SHA1_WITH_RSA);

        SigningAlgorithm algo;
        Algo(SigningAlgorithm algo) {
            this.algo = algo;
        }
    }

    /**
     * create DKIM messages at certain moment, then store those messages as "valid message".
     */
    public static void main(String[] args) throws Exception {
        createRandomBody();
        File[] files = new File("./src/test/resources/body").listFiles();
        for (File file : files) {
            String body = new String(Utils.read(file));
            for (Cannon c : Cannon.values()) {
                for (Algo a : Algo.values()) {
                    DkimSigner signer = mkSigner(c.cannon, a.algo);
                    String name = a.name()+"_"+c.name();
                    byte[] bytes = writeMsg(signer, body);
                    Utils.write(new File("./src/test/resources/" + name, file.getName()), bytes);
                }
            }
        }
    }

    private static void createRandomBody() throws IOException {
        Random rand = new Random();
        for (int i = 0; i < 50; i++) {
            int length = rand.nextInt(2000) + 100;
            String body = Utils.randomString(length);
            Utils.write(new File("./src/test/resources/body", "random"+(i+1)+".txt"), body.getBytes());
        }
    }
    
    @Before
	public void fixateSystemTimeZone() {
		System.setProperty("user.timezone", "JST");
	}

	@Test
	public void testCreatingSameMessageAsBefore() throws Exception {
        File[] files = new File("./src/test/resources/body").listFiles();
        for (File file : files) {
            String body = new String(Utils.read(file));
            for (Cannon c : Cannon.values()) {
                for (Algo a : Algo.values()) {
                    DkimSigner signer = mkSigner(c.cannon, a.algo);
                    String name = a.name()+"_"+c.name();
                    byte[] actual = writeMsg(signer, body);
                    byte[] expected = Utils.read(new File("./src/test/resources/" + name, file.getName()));
                    assertArrayEquals("body:" + file.getName() + ", algorithm:" + name, expected, actual);
                }
            }
        }
	}

	private static DkimSigner mkSigner(Canonicalization canonicalization, SigningAlgorithm algorithm) throws Exception {
		// signer
		DkimSigner signer = new DkimSigner("example.com", "dkim1", new File("./src/test/resources/key/dkim.der"));
		signer.setHeaderCanonicalization(canonicalization);
		signer.setBodyCanonicalization(canonicalization);
		signer.setLengthParam(true);
		signer.setSigningAlgorithm(algorithm);
		signer.setZParam(false);
		signer.setCheckDomainKey(false);

		return signer;
	}

	private static byte[] writeMsg(DkimSigner signer, String body) throws Exception {
		// Session
		Properties properties=new Properties();
		properties.setProperty("mail.smtp.host", "exapmle.com");
		properties.setProperty("mail.from", "foo@exapmle.com");
		properties.setProperty("mail.smtp.from", "exapmle.com");
		Session session=Session.getDefaultInstance(properties);
		// Message
		MimeMessage message = new MimeMessage(session) {
            @Override // bind "Message-ID"
            protected void updateMessageID() throws MessagingException {
                super.updateMessageID();
                String msgId = getHeader("Message-ID")[0];
                String addr = msgId.substring(1, msgId.length() - 1);
                int i = addr.lastIndexOf('@');
                this.setHeader("Message-ID", "<msgid"+addr.substring(i)+">");
            }
        };
        message.setSentDate(new Date((long)1e9)); // to bind "t" parameter, set constant date as "Signature Timestamp"
		message.setRecipient(Message.RecipientType.TO, new InternetAddress("test@exapmle.com"));
		message.setSubject("Title");
		message.setFrom("support@example.com");
		message.setText(body, "US-ASCII", "plain");
		message.setHeader("Content-Transfer-Encoding", "7bit");
		message.setHeader("Content-Type", "text/plain; charset=\"US-ASCII\"");
		message.saveChanges();

		DkimMessage dkimMessage = new DkimMessage(message, signer);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        dkimMessage.writeTo(out);
		return out.toByteArray();
	}

}
