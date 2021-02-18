package net.markenwerk.utils.mail.dkim;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;

import net.markenwerk.commons.nulls.NullOutputStream;
import net.markenwerk.utils.data.fetcher.BufferedDataFetcher;

class Utils {

	static String randomString(Random random, int length) {
		char[] chars = new char[length];
		for (int i = 0; i < length; i++) {
			int v = random.nextInt(0x60 + 6); // [0x20, 0x7f] + ctrl*6
			char c;
			if (v == 0) {
				c = '\r'; // carriage return
			} else if (v == 1) {
				c = '\n'; // line feed
			} else if (v == 2) {
				c = ' '; // space
			} else if (v == 3) {
				c = '\f'; // vertical tab
			} else if (v == 4) {
				c = '\u000b'; // form feed
			} else if (v == 5) {
				c = '\t'; // horizontal tab
			} else {
				c = (char) (v - 6 + 0x20); // [0x20, 0x7f]
			}
			chars[i] = c;
		}
		return new String(chars);
	}

	static byte[] read(File file) throws IOException {
		return new BufferedDataFetcher().fetch(new FileInputStream(file), true);
	}

	static void write(File file, byte[] bytes) throws IOException {
		new BufferedDataFetcher().copy(new ByteArrayInputStream(bytes), new FileOutputStream(file));
	}

	static String digest(String string, String algorithm) throws IOException, NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance(algorithm);
		DigestOutputStream out = new DigestOutputStream(new NullOutputStream(), digest);
		new BufferedDataFetcher().copy(new ByteArrayInputStream(string.getBytes()), out, true, true);
		return Base64.getEncoder().encodeToString(digest.digest());
	}

	static DkimSigner getSigner(Canonicalization canonicalization, SigningAlgorithm algorithm) throws Exception {

		DkimSigner signer = new DkimSigner("example.com", "dkim1", new File("./src/test/resources/key/dkim.der"));
		signer.setHeaderCanonicalization(canonicalization);
		signer.setBodyCanonicalization(canonicalization);
		signer.setLengthParam(true);
		signer.setSigningAlgorithm(algorithm);
		signer.setCopyHeaderFields(false);
		signer.setCheckDomainKey(false);

		return signer;

	}

}
