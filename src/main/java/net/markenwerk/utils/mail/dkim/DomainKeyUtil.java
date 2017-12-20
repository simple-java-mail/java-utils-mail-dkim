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

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

/**
 * @author Torsten Krause (tk at markenwerk dot net)
 * @author Florian Sager
 * @since 1.0.0
 */
public final class DomainKeyUtil {

	private static final Map<String, DomainKey> CACHE = new HashMap<String, DomainKey>();

	private static final long DEFAULT_CACHE_TTL = 2 * 60 * 60 * 1000;

	private static long cacheTtl = DEFAULT_CACHE_TTL;

	private DomainKeyUtil() {
	}

	/**
	 * Returns the configured TTL (time to live) for retrieved {@link DomainKey} s.
	 * 
	 * @return The configured TTL for retrieved {@link DomainKey}s.
	 */
	public static synchronized long getCacheTtl() {
		return cacheTtl;
	}

	/**
	 * Sets the TTL (time to live) for retrieved {@link DomainKey}s.
	 * 
	 * @param cacheTtl
	 *            The TTL for retrieved {@link DomainKey}s.
	 */
	public static synchronized void setCacheTtl(long cacheTtl) {
		if (cacheTtl < 0) {
			cacheTtl = DEFAULT_CACHE_TTL;
		}
		DomainKeyUtil.cacheTtl = cacheTtl;
	}

	/**
	 * Retrieves the {@link DomainKey} for the given signing domain and selector.
	 * 
	 * @param signingDomain
	 *            The signing domain.
	 * @param selector
	 *            The selector.
	 * @return The retrieved {@link DomainKey}.
	 * @throws DkimException
	 *             If the domain key couldn't be retrieved or if either the version,
	 *             key type or service type given in the tags of the retrieved
	 *             domain key is incompatible to this library ('DKIM1', 'RSA' and
	 *             'email' respectively).
	 */
	public static synchronized DomainKey getDomainKey(String signingDomain, String selector) throws DkimException {
		return getDomainKey(getRecordName(signingDomain, selector));
	}

	private static synchronized DomainKey getDomainKey(String recordName) throws DkimException {
		DomainKey domainKey = CACHE.get(recordName);
		if (null != domainKey) {
			if (0 == cacheTtl || domainKey.getTimestamp() + cacheTtl > System.currentTimeMillis()) {
				return domainKey;
			}
		}
		domainKey = fetchDomainKey(recordName);
		CACHE.put(recordName, domainKey);
		return domainKey;
	}

	private static DomainKey fetchDomainKey(String recordName) throws DkimException {
		return new DomainKey(getTags(recordName));
	}

	/**
	 * Retrieves the tags of a domain key for the given signing domain and selector.
	 * 
	 * @param signingDomain
	 *            The signing domain.
	 * @param selector
	 *            The selector.
	 * @return The retrieved tags.
	 * @throws DkimException
	 *             If the domain key couldn't be retrieved.
	 */
	public static Map<Character, String> getTags(String signingDomain, String selector) throws DkimException {
		return getTags(getRecordName(signingDomain, selector));
	}

	private static Map<Character, String> getTags(String recordName) throws DkimException {
		Map<Character, String> tags = new HashMap<Character, String>();

		String unquotedRecordValue = unquoteRecordValue(getValue(recordName));

		for (String tag : unquotedRecordValue.split(";")) {
			try {
				tag = tag.trim();
				tags.put(tag.charAt(0), tag.substring(2));
			} catch (IndexOutOfBoundsException e) {
				throw new DkimException("The tag " + tag + " in RR " + recordName + " couldn't be decoded.", e);
			}
		}
		return tags;
	}

	/**
	 * Unquote a recordValue string.
	 *
	 * @param recordValue
	 *            Domain record value.
	 * @return Domain record value unquoted.
	 */
	private static String unquoteRecordValue(String recordValue) {

		if (recordValue != null && ((recordValue.startsWith("\"") && recordValue.endsWith("\""))
				|| (recordValue.startsWith("'") && recordValue.endsWith("'")))) {

			recordValue = recordValue.substring(1, recordValue.length() - 1);
		}
		return recordValue;
	}

	/**
	 * Retrieves the raw domain key for the given signing domain and selector.
	 * 
	 * @param signingDomain
	 *            The signing domain.
	 * @param selector
	 *            The selector.
	 * @return The raw domain key.
	 * @throws DkimException
	 *             If the domain key couldn't be retrieved.
	 */
	public static String getValue(String signingDomain, String selector) throws DkimException {
		return getValue(getRecordName(signingDomain, selector));
	}

	private static String getValue(String recordName) throws DkimException {
		try {
			DirContext dnsContext = new InitialDirContext(getEnvironment());
			Attributes attributes = dnsContext.getAttributes(recordName, new String[] { "TXT" });
			Attribute txtRecord = attributes.get("txt");

			if (txtRecord == null) {
				throw new DkimException("There is no TXT record available for " + recordName);
			}

			StringBuilder builder = new StringBuilder();
			NamingEnumeration<?> e = txtRecord.getAll();
			while (e.hasMore()) {
				builder.append((String) e.next());
			}

			String value = builder.toString();
			if (value.isEmpty()) {
				throw new DkimException("Value of RR " + recordName + " couldn't be retrieved");
			}
			return value;

		} catch (NamingException ne) {
			throw new DkimException("Selector lookup failed", ne);
		}
	}

	private static String getRecordName(String signingDomain, String selector) {
		return selector + "._domainkey." + signingDomain;
	}

	private static Hashtable<String, String> getEnvironment() {
		Hashtable<String, String> environment = new Hashtable<String, String>();
		environment.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
		return environment;
	}

}
