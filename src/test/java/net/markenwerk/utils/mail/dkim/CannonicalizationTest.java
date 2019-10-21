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

	@Test
	public void checkSpaceOnlyBody() throws Exception {

		checkBody(" \t", " \t\r\n", "", "space only body");
		checkBody(" \t\f\u000b \t",
                " \t\f\u000b \t\r\n",   // all spaces are preserved
                " \f\u000b\r\n",       // SP's and HT's are reduced to one SP, SP's at line end is removed, form feeds and VT's are preserved
                "reducing space of relaxed's algorithm ignores form feeds and vertical tabs"
        );

	}

	@Test
	public void checkSpaceAndCRLFBody() throws Exception {

		checkBody(" \t\r\n \t", " \t\r\n \t\r\n", "", "space and crlf only body");

	}

	private void checkBody(String body, String simpleResult, String relaxedResult, String description) {

		checkBody(Canonicalization.SIMPLE, body, simpleResult, description);
		checkBody(Canonicalization.RELAXED, body, relaxedResult, description);

	}

	private void checkBody(Canonicalization canonicalization, String body, String result, String description) {

		assertEquals(canonicalization.name() + " / " + description, result, canonicalization.canonicalizeBody(body));

	}

}
