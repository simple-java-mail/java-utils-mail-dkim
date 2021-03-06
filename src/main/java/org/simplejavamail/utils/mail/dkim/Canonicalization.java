package org.simplejavamail.utils.mail.dkim;

/**
 * Provides "simple" and "relaxed" canonicalization according to RFC 4871.
 * 
 * @author Torsten Krause (tk at markenwerk dot net)
 * @author Florian Sager
 * @since 1.0.0
 */
public enum Canonicalization {

	/**
	 * The "simple" canonicalization algorithm.
	 * 
	 * The body canonicalization algorithm converts *CRLF at the end of the body to
	 * a single CRLF.
	 */
	SIMPLE {

		public String canonicalizeHeader(String name, String value) {
			return name + ": " + value;
		}

		public String canonicalizeBody(String body) {

			// if there is no body, CRLF is returned
			if (body == null) {
				return "\r\n";
			}

			// if there is no trailing CRLF on the message body, CRLF is added
			if (!body.endsWith("\r\n")) {
				return body + "\r\n";
			}

			// while there are multiple trailing CRLF on the message body, one is removed
			while (body.endsWith("\r\n\r\n")) {
				body = body.substring(0, body.length() - 2);
			}

			return body;

		}
	},

	/**
	 * The "relaxed" canonicalization algorithm.
	 * 
	 * The body canonicalization algorithm MUST reduce whitespace and ignore all
	 * empty lines at the end of the message body.
	 */
	RELAXED {

		public String canonicalizeHeader(String name, String value) {
			return name.trim().toLowerCase() + ":" + value.replaceAll("\\s+", " ").trim();
		}

		public String canonicalizeBody(String body) {

			// if there is no body, an empty body is returned
			if (body == null) {
				return "";
			}

			// if there is no trailing CRLF on the message body, CRLF is added
			if (!body.endsWith("\r\n")) {
				body += "\r\n";
			}

			// ignore all whitespace at the end of lines
			body = body.replaceAll("[ \\t]+\r\n", "\r\n");

			// reduce all sequences of whitespace within a line to a single SP character
			body = body.replaceAll("[ \\t]+", " ");

			// while there are multiple trailing CRLF on the message body, one is removed
			while (body.endsWith("\r\n\r\n")) {
				body = body.substring(0, body.length() - 2);
			}

			// at last, ensure CRLF is empty
			if ("\r\n".equals(body)) {
				body = "";
			}

			return body;

		}
	};

	public final String getType() {
		return name().toLowerCase();
	}

	public abstract String canonicalizeHeader(String name, String value);

	public abstract String canonicalizeBody(String body);
	
}
