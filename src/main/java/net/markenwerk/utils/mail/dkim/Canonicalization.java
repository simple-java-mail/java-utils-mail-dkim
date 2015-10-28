/*
 * Copyright (c) 2015 Torsten Krause, Markenwerk GmbH.
 * 
 * This file is part of 'A DKIM library for JavaMail', hereafter
 * called 'this library', identified by the following coordinates:
 * 
 *    groupID: net.markenwerk
 *    artifactId: utils-mail-dkim
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 * 
 * See the LICENSE and NOTICE files in the root directory for further
 * information.
 * 
 * This file incorporates work covered by the following copyright and  
 * permission notice:
 *  
 *    Copyright 2008 The Apache Software Foundation or its licensors, as
 *    applicable.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 *    A licence was granted to the ASF by Florian Sager on 30 November 2008
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
			if (!"\r\n".equals(body.substring(body.length() - 2, body.length()))) {
				return body + "\r\n";
			}

			// Remove trailing empty lines ...
			while ("\r\n\r\n".equals(body.substring(body.length() - 4, body.length()))) {
				body = body.substring(0, body.length() - 2);
			}

			return body;
		}
	},

	/**
	 * The 'relaxed' canonicalization algorithm.
	 */
	RELAXED {

		public String canonicalizeHeader(String name, String value) {
			name = name.trim().toLowerCase();
			value = value.replaceAll("\\s+", " ").trim();
			return name + ": " + value;
		}

		public String canonicalizeBody(String body) {

			if (body == null || "".equals(body)) {
				return "\r\n";
			}

			body = body.replaceAll("[ \\t\\x0B\\f]+", " ");
			body = body.replaceAll(" \r\n", "\r\n");

			// The body must end with \r\n
			if (!"\r\n".equals(body.substring(body.length() - 2, body.length()))) {
				return body + "\r\n";
			}

			// Remove trailing empty lines ...
			while ("\r\n\r\n".equals(body.substring(body.length() - 4, body.length()))) {
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
