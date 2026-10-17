package org.simplejavamail.utils.mail.dkim;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CannonicalizationTest {

	private static Stream<Arguments> bodies() {
		List<Arguments> cases = new ArrayList<Arguments>();
		addBody(cases, "null", null, "\r\n", "");
		addBody(cases, "empty", "", "\r\n", "");
		addBody(cases, "single empty line", "\r\n", "\r\n", "");
		addBody(cases, "multiple empty lines", "\r\n\r\n\r\n", "\r\n", "");
		addBody(cases, "space and tab only", " \t", " \t\r\n", "");
		addBody(cases, "whitespace lines", " \t\r\n \t", " \t\r\n \t\r\n", "");
		addBody(cases, "missing final CRLF", "hello", "hello\r\n", "hello\r\n");
		addBody(cases, "existing final CRLF", "hello\r\n", "hello\r\n", "hello\r\n");
		addBody(cases, "trailing empty lines", "hello\r\n\r\n\r\n", "hello\r\n", "hello\r\n");
		addBody(cases, "leading empty line", "\r\nhello\r\n", "\r\nhello\r\n", "\r\nhello\r\n");
		addBody(cases, "interior empty line", "one\r\n\r\ntwo", "one\r\n\r\ntwo\r\n", "one\r\n\r\ntwo\r\n");
		addBody(cases, "leading whitespace", " \tXY \t", " \tXY \t\r\n", " XY\r\n");
		addBody(cases, "horizontal whitespace", "A \t \tB\t C \t", "A \t \tB\t C \t\r\n", "A B C\r\n");
		addBody(cases, "trailing whitespace line", "A\r\n \t", "A\r\n \t\r\n", "A\r\n");
		addBody(cases, "interior whitespace line", "A\r\n \t\r\nB\r\n", "A\r\n \t\r\nB\r\n", "A\r\n\r\nB\r\n");
		addBody(cases, "RFC 6376 example", " C \r\nD \t E\r\n\r\n\r\n", " C \r\nD \t E\r\n", " C\r\nD E\r\n");
		addBody(cases, "non-whitespace controls", " \t\f\u000b \t", " \t\f\u000b \t\r\n", " \f\u000b\r\n");
		addBody(cases, "null byte", "A\u0000B \t", "A\u0000B \t\r\n", "A\u0000B\r\n");
		addBody(cases, "nonbreaking space", "A\u00a0B\u00a0", "A\u00a0B\u00a0\r\n", "A\u00a0B\u00a0\r\n");
		addBody(cases, "Unicode text", "Caf\u00e9 \u65e5\u672c\u8a9e \t", "Caf\u00e9 \u65e5\u672c\u8a9e \t\r\n", "Caf\u00e9 \u65e5\u672c\u8a9e\r\n");
		return cases.stream();
	}

	private static void addBody(List<Arguments> cases, String description, String body, String simple, String relaxed) {
		cases.add(Arguments.of(description, Canonicalization.SIMPLE, body, simple));
		cases.add(Arguments.of(description, Canonicalization.RELAXED, body, relaxed));
	}

	@ParameterizedTest(name = "{0}: {1}")
	@MethodSource("bodies")
	public void canonicalizesBodies(String description, Canonicalization canonicalization, String body, String expected) {
		assertEquals(expected, canonicalization.canonicalizeBody(body), description);
	}

	private static Stream<Arguments> headers() {
		return Stream.of(
				Arguments.of(Canonicalization.SIMPLE, "Subject", "Hello", "Subject: Hello"),
				Arguments.of(Canonicalization.SIMPLE, "SUBJECT", " \tHello \t", "SUBJECT:  \tHello \t"),
				Arguments.of(Canonicalization.SIMPLE, "Subject", "", "Subject: "),
				Arguments.of(Canonicalization.SIMPLE, "Subject", "one\r\n\ttwo", "Subject: one\r\n\ttwo"),
				Arguments.of(Canonicalization.RELAXED, "SUBJECT", "Hello", "subject:Hello"),
				Arguments.of(Canonicalization.RELAXED, "Subject", " \tHello \t", "subject:Hello"),
				Arguments.of(Canonicalization.RELAXED, "Subject", "", "subject:"),
				Arguments.of(Canonicalization.RELAXED, "Subject", "one\r\n\ttwo", "subject:one two"),
				Arguments.of(Canonicalization.RELAXED, "Subject \t", " A \t\r\n \t B \t", "subject:A B"),
				Arguments.of(Canonicalization.RELAXED, "Subject", "Caf\u00e9\u00a0", "subject:Caf\u00e9\u00a0"));
	}

	@ParameterizedTest(name = "{0}: {1}")
	@MethodSource("headers")
	public void canonicalizesHeaders(Canonicalization canonicalization, String name, String value, String expected) {
		assertEquals(expected, canonicalization.canonicalizeHeader(name, value));
	}
}
