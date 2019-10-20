package net.markenwerk.utils.mail.dkim;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class CannonicalizationTest {

	@Test
	public void checkNullBody() throws Exception {

		checkBody((String) null, "\r\n", "", "empty body");

	}

	@Test
	public void checkEmptyBody() throws Exception {

		checkBody("", "\r\n", "", "empty body");

	}

	private void checkBody(String body, String simpleResult, String relaxedResult, String description) {

		checkBody(Canonicalization.SIMPLE, body, simpleResult, description);
		checkBody(Canonicalization.RELAXED, body, relaxedResult, description);

	}

	private void checkBody(Canonicalization canonicalization, String body, String result, String description) {

		assertEquals(canonicalization.name() + " / " + description, result, canonicalization.canonicalizeBody(body));

	}

}
