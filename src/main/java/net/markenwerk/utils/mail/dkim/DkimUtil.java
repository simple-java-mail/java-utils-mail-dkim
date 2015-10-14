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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import com.sun.mail.util.QPEncoderStream;
import net.iharder.Base64;

/**
 * @author Torsten Krause (tk at markenwerk dot net)
 * @author Florian Sager
 * @since 1.0.0
 */
public final class DkimUtil {

	private static final String RSA_MODE = "RSA/ECB/NoPadding";

	private static class Entry {

		private final long timestamp;

		private final Pattern granularity;

		private final RSAPublicKey publicKey;

		public Entry(long timestamp, Pattern granularity, RSAPublicKey publicKey) {
			super();
			this.timestamp = timestamp;
			this.granularity = granularity;
			this.publicKey = publicKey;
		}

		@Override
		public String toString() {
			return "Entry [timestamp=" + timestamp + ", granularity=" + granularity + ", publicKey=" + publicKey + "]";
		}

	}

	private static final Map<String, Entry> CACHE = new HashMap<>();

	private static final long DEFAULT_CACHE_TTL = 2 * 60 * 60 * 1000;

	private static long cacheTtl = DEFAULT_CACHE_TTL;

	private DkimUtil() {
	}

	// protected static String[] splitHeader(String header) throws DkimException
	// {
	// int colonPosition = header.indexOf(':');
	// if (-1 == colonPosition) {
	// throw new DkimException("The header string " + header +
	// " is no valid RFC 822 header-line");
	// }
	// return new String[] { header.substring(0, colonPosition),
	// header.substring(colonPosition + 1) };
	// }

	protected static String concatArray(List<String> assureHeaders, String separator) {
		StringBuffer buffer = new StringBuffer();
		for (String string : assureHeaders) {
			buffer.append(string);
			buffer.append(separator);
		}
		return buffer.substring(0, buffer.length() - separator.length());
	}

	protected static boolean isValidDomain(String domainname) {
		Pattern pattern = Pattern.compile("(.+)\\.(.+)");
		Matcher matcher = pattern.matcher(domainname);
		return matcher.matches();
	}

	// FSTODO: converts to "platforms default encoding" might be wrong ?
	protected static String QuotedPrintable(String s) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			QPEncoderStream encodeStream = new QPEncoderStream(out);
			encodeStream.write(s.getBytes());
			encodeStream.close();

			String encoded = out.toString();
			encoded = encoded.replaceAll(";", "=3B");
			encoded = encoded.replaceAll(" ", "=20");

			return encoded;
		} catch (IOException e) {
			return null;
		}
	}

	protected static String base64Encode(byte[] bytes) {
		String encoded = Base64.encodeBytes(bytes);

		// remove unnecessary line feeds after 76 characters
		encoded = encoded.replace("\n", "");
		encoded = encoded.replace("\r", "");

		return encoded;
	}

	public static synchronized long getCacheTtl() {
		return cacheTtl;
	}

	public static synchronized void setCacheTtl(long cacheTtl) {
		if (cacheTtl < 0) {
			cacheTtl = DEFAULT_CACHE_TTL;
		}
		DkimUtil.cacheTtl = cacheTtl;
	}

	public static DkimAcceptance checkDomainKey(String signingDomain, String selector, String from,
			RSAPrivateKey privateKey) throws DkimException {

		String recordName = getRecordName(signingDomain, selector);
		Entry entry = getEntry(recordName);

		String localPart = from.substring(0, from.indexOf('@'));
		if (!entry.granularity.matcher(localPart).matches()) {
			return DkimAcceptance.INCOMPATIBLE_GRANULARITY;
		}

		try {
			RSAPublicKey publicKey = entry.publicKey;

			// prepare cipher and message
			Cipher cipher = Cipher.getInstance(RSA_MODE);
			byte[] originalMessage = new byte[publicKey.getModulus().bitLength() / Byte.SIZE];
			for (int i = 0, n = originalMessage.length; i < n; i++) {
				originalMessage[i] = (byte) i;
			}

			// encrypt original message
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			byte[] encryptedMessage = cipher.doFinal(originalMessage);

			// decrypt encrypted message
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			byte[] decryptedMessage = cipher.doFinal(encryptedMessage);

			if (Arrays.equals(originalMessage, decryptedMessage)) {
				return DkimAcceptance.OKAY;
			} else {
				return DkimAcceptance.INCOMPATIBLE_PUBLIC_KEY;
			}

		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new DkimException("No JCE provider supports " + RSA_MODE + " ciphers.", e);
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			throw new DkimException("Performing RSA cryptography failed.", e);
		}
	}

	private static synchronized Entry getEntry(String recordName) {
		Entry entry = CACHE.get(recordName);
		if (null != entry) {
			if (0 == cacheTtl || entry.timestamp + cacheTtl > System.currentTimeMillis()) {
				return entry;
			}
		}
		entry = getEntryFromDns(recordName);
		CACHE.put(recordName, entry);
		return entry;
	}

	private static Entry getEntryFromDns(String recordName) {

		Map<Character, String> tagValues = getTagsFromDns(recordName);
		Pattern granularity = getGranularityPattern(tagValues.get('g'));
		String privateKeyTagValue = tagValues.get('p');
		if (null == privateKeyTagValue) {
			throw new DkimException("No public key available for " + recordName);
		}

		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.decode(privateKeyTagValue));
			RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
			return new Entry(System.currentTimeMillis(), granularity, publicKey);
		} catch (NoSuchAlgorithmException nsae) {
			throw new DkimException("RSA algorithm not found by JVM");
		} catch (IOException | InvalidKeySpecException ikse) {
			throw new DkimException("The public key " + privateKeyTagValue + " in RR " + recordName
					+ " couldn't be decoded.");
		}

	}

	public static Map<Character, String> getTagsFromDns(String signingDomain, String selector) {
		return getTagsFromDns(getRecordName(signingDomain, selector));
	}

	private static Map<Character, String> getTagsFromDns(String recordName) {
		Map<Character, String> tags = new HashMap<>();
		for (String tag : getValueFromDns(recordName).split(";")) {
			try {
				tag = tag.trim();
				tags.put(tag.charAt(0), tag.substring(2));
			} catch (IndexOutOfBoundsException e) {
				throw new DkimException("The tag " + tag + " in RR " + recordName + " couldn't be decoded.", e);
			}
		}
		return tags;
	}

	private static final Pattern getGranularityPattern(String granularity) {
		if (null == granularity) {
			return Pattern.compile(".*");
		}
		StringTokenizer tokenizer = new StringTokenizer(granularity, "*", true);
		StringBuffer pattern = new StringBuffer();
		while (tokenizer.hasMoreElements()) {
			String token = tokenizer.nextToken();
			if ("*".equals(token)) {
				pattern.append(".*");
			} else {
				pattern.append(Pattern.quote(token));
			}
		}
		return Pattern.compile(pattern.toString());
	}

	private static String getRecordName(String signingDomain, String selector) {
		return selector + "._domainkey." + signingDomain;
	}

	public static String getValueFromDns(String signingDomain, String selector) {
		return getValueFromDns(getRecordName(signingDomain, selector));
	}

	private static String getValueFromDns(String recordName) {
		try {
			DirContext dnsContext = new InitialDirContext(getEnvironment());
			Attributes attributes = dnsContext.getAttributes(recordName, new String[] { "TXT" });
			Attribute txtRecord = attributes.get("txt");

			if (txtRecord == null) {
				throw new DkimException("There is no TXT record available for " + recordName);
			}

			// "v=DKIM1; g=*; k=rsa; p=MIGfMA0G ..."
			String value = (String) txtRecord.get();
			if (null == value) {
				throw new DkimException("Value of RR " + recordName + " couldn't be retrieved");
			}
			return value;

		} catch (NamingException ne) {
			throw new DkimException("Selector lookup failed", ne);
		}
	}

	private static Hashtable<String, String> getEnvironment() {
		Hashtable<String, String> environment = new Hashtable<String, String>();
		environment.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
		return environment;
	}

}
