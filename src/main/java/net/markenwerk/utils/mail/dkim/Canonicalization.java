/* 
 * Copyright 2008 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * A licence was granted to the ASF by Florian Sager on 30 November 2008
 */
package net.markenwerk.utils.mail.dkim;

/**
 * Provides 'simple' and 'relaxed' canonicalization according to RFC 4871.
 * 
 * @author Torsten Krause (tk at markenwerk dot net)
 * @author Florian Sager
 * @since 1.0.0
 */
public enum Canonicalization {

	/**
	 * The 'simple' canonicalization algorithm.
	 * Note that a completely empty or missing body is canonicalized as a
	 *    single "CRLF"; that is, the canonicalized length will be 2 octets.
	 *
	 *    The SHA-1 value (in base64) for an empty body (canonicalized to a "CRLF") is:
	 *
	 *    uoq1oCgLlTqpdDX/iUbLy7J1Wic=
	 *
	 *    The SHA-256 value is:
	 *
	 *    frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=
	 */
	SIMPLE {

		public String canonicalizeHeader(String name, String value) {
			return name + ": " + value;
		}

		public String canonicalizeBody(String body) {

			if (body == null || "".equals(body)) {
				return "\r\n";
			}

			// The body must end with \r\n
			if (!body.endsWith("\r\n")) {
				return body + "\r\n";
			}

			// Remove trailing empty lines ...
			while (body.endsWith("\r\n\r\n")) {
				body = body.substring(0, body.length() - 2);
			}

			return body;
		}
	},

	/**
	 * The 'relaxed' canonicalization algorithm.
	 *
	 * The SHA-1 value (in base64) for an empty body (canonicalized to a
	 *    null input) is:
	 *
	 *    2jmj7l5rSw0yVb/vlWAYkK/YBwk=
	 *
	 *    The SHA-256 value is:
	 *
	 *    47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
	 */
	RELAXED {

		public String canonicalizeHeader(String name, String value) {
			name = name.trim().toLowerCase();
			value = value.replaceAll("\\s+", " ").trim();
			return name + ":" + value;
		}

		public String canonicalizeBody(String body) {

			if (body == null || "".equals(body) || "\r\n".equals(body)) {
				return "";
			}

			body = body.replaceAll("[ \\t\\x0B\\f]+", " ");
			body = body.replaceAll(" \r\n", "\r\n");

			// The body must end with \r\n
			if (!body.endsWith("\r\n")) {
				return body + "\r\n";
			}

			// Remove trailing empty lines ...
			while (body.endsWith("\r\n\r\n")) {
				body = body.substring(0, body.length() - 2);
			}

			return body;
		}
	};

	/**
	 * Returns a string representation of the canonicalization algorithm.
	 * 
	 * @return The string representation of the canonicalization algorithm.
	 */
	public final String getType() {
		return name().toLowerCase();
	}

	/**
	 * Performs header canonicalization.
	 * 
	 * @param name
	 *            The name of the header.
	 * @param value
	 *            The value of the header.
	 * @return The canonicalized header.
	 */
	public abstract String canonicalizeHeader(String name, String value);

	/**
	 * Performs body canonicalization.
	 * 
	 * @param body
	 *            The content of the body.
	 * @return The canonicalized body.
	 */
	public abstract String canonicalizeBody(String body);
}
