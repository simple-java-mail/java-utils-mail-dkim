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

	private static final Map<String, DomainKey> CACHE = new HashMap<>();

	private static final long DEFAULT_CACHE_TTL = 2 * 60 * 60 * 1000;

	private static long cacheTtl = DEFAULT_CACHE_TTL;

	private DomainKeyUtil() {
	}

	public static synchronized long getCacheTtl() {
		return cacheTtl;
	}

	public static synchronized void setCacheTtl(long cacheTtl) {
		if (cacheTtl < 0) {
			cacheTtl = DEFAULT_CACHE_TTL;
		}
		DomainKeyUtil.cacheTtl = cacheTtl;
	}

	public static synchronized DomainKey getDomainKey(String signingDomain, String selector) throws DkimException {
		return getDomainKey(getRecordName(signingDomain, selector));
	}

	private static synchronized DomainKey getDomainKey(String recordName) throws DkimException {
		DomainKey entry = CACHE.get(recordName);
		if (null != entry) {
			if (0 == cacheTtl || entry.getTimestamp() + cacheTtl > System.currentTimeMillis()) {
				return entry;
			}
		}
		entry = fetchDomainKey(recordName);
		CACHE.put(recordName, entry);
		return entry;
	}

	private static DomainKey fetchDomainKey(String recordName) throws DkimException {
		return new DomainKey(getTags(recordName));
	}

	public static Map<Character, String> getTags(String signingDomain, String selector) throws DkimException {
		return getTags(getRecordName(signingDomain, selector));
	}

	private static Map<Character, String> getTags(String recordName) throws DkimException {
		Map<Character, String> tags = new HashMap<>();
		for (String tag : getValue(recordName).split(";")) {
			try {
				tag = tag.trim();
				tags.put(tag.charAt(0), tag.substring(2));
			} catch (IndexOutOfBoundsException e) {
				throw new DkimException("The tag " + tag + " in RR " + recordName + " couldn't be decoded.", e);
			}
		}
		return tags;
	}

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

			String value = (String) txtRecord.get();
			if (null == value) {
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
