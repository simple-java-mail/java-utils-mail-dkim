package org.simplejavamail.utils.mail.dkim;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class CannonicalizationTest {

	@Test
	public void checkNullBody() throws Exception {

		checkBody((String) null, "\r\n", "", "empty body");

	}

	@Test
	public void checkEmptyBody() throws Exception {

		checkBody("", "\r\n", "", "empty body");

	}

	@Test
	public void checkWhitespaceOnlyBody() throws Exception {

		checkBody(" \t", " \t\r\n", "", "whitespace-only body");

	}

	@Test
	public void checkCharactersWithinWhitespaceOnlyBody() throws Exception {

		checkBody(" \tXY \t", " \tXY \t\r\n", " XY\r\n", "characters within whitespace");

	}

	@Test
	public void checkControlCharactersWithinWhitespaceOnlyBody() throws Exception {

		checkBody(" \t\f\u000b \t", " \t\f\u000b \t\r\n", " \f\u000b\r\n", "control characters within whitespace");

	}

	@Test
	public void checkSpaceAndCRLFBody() throws Exception {

		checkBody(" \t\r\n \t", " \t\r\n \t\r\n", "", "space-and-crlf-only body");

	}

	@Test
	public void checkRfcExampleBody() throws Exception {

		checkBody(" C \r\nD \t E\r\n\r\n\r\n", " C \r\nD \t E\r\n", " C\r\nD E\r\n", "example body from rfc");

	}

	private void checkBody(String body, String simpleResult, String relaxedResult, String description) {

		checkBody(Canonicalization.SIMPLE, body, simpleResult, description);
		checkBody(Canonicalization.RELAXED, body, relaxedResult, description);

	}

	private void checkBody(Canonicalization canonicalization, String body, String actual, String description) {
		String expected = canonicalization.name() + " / " + description;
		String message = canonicalization.canonicalizeBody(body);
		assertThat(actual).as(message).isEqualTo(expected);
	}
}