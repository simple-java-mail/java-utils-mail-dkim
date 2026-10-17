package org.simplejavamail.utils.mail.dkim;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertThrows;

/** Validates the independent oracle against retained signed messages. */
class SignatureAssertionsTest {

	private static Stream<String> signatureConfigurations() {
		return Stream.of("sha1_simple", "sha1_relaxed", "sha256_simple", "sha256_relaxed");
	}

	@ParameterizedTest
	@MethodSource("signatureConfigurations")
	void verifiesRetainedSignatures(String configuration) throws Exception {
		SignatureAssertions.assertValidSignature(fixture(configuration), publicKey());
	}

	@ParameterizedTest
	@MethodSource("signatureConfigurations")
	void rejectsAlteredBody(String configuration) throws Exception {
		byte[] wire = fixture(configuration);
		wire[wire.length - 1] = 'X';
		assertThrows(AssertionError.class, () -> SignatureAssertions.assertValidSignature(wire, publicKey()));
	}

	@ParameterizedTest
	@MethodSource("signatureConfigurations")
	void rejectsAlteredSignedHeader(String configuration) throws Exception {
		String wire = new String(fixture(configuration), StandardCharsets.ISO_8859_1);
		byte[] altered = wire.replace("Subject: Title", "Subject: Altered").getBytes(StandardCharsets.ISO_8859_1);
		assertThrows(AssertionError.class, () -> SignatureAssertions.assertValidSignature(altered, publicKey()));
	}

	private static byte[] fixture(String configuration) throws Exception {
		return Utils.read(new File("src/test/resources/" + configuration + "/simple1.txt"));
	}

	private static PublicKey publicKey() throws Exception {
		String pem = new String(Utils.read(new File("src/test/resources/key/dkim.pub")), StandardCharsets.US_ASCII);
		String base64 = pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replaceAll("\\s", "");
		return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64)));
	}
}
