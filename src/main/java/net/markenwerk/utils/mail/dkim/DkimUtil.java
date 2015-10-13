/*
 * Copyright (C) 2015 Torsten Krause.
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
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

	private DkimUtil() {
	}

	protected static String[] splitHeader(String header) throws DkimException {
		int colonPosition = header.indexOf(':');
		if (-1 == colonPosition) {
			throw new DkimException("The header string " + header + " is no valid RFC 822 header-line");
		}
		return new String[] { header.substring(0, colonPosition), header.substring(colonPosition + 1) };
	}

	protected static String concatArray(ArrayList<String> list, String separator) {
		StringBuffer buffer = new StringBuffer();
		for (String string : list) {
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

	public boolean checkDNSForPublickey(String signingDomain, String selector) throws DkimException {

		String recordName = getRecordName(signingDomain, selector);
		String value = getValueFromDns(recordName);

		// try to read public key from RR
		String[] tags = value.split(";");
		for (String tag : tags) {
			tag = tag.trim();
			if (tag.startsWith("p=")) {

				try {
					KeyFactory keyFactory = KeyFactory.getInstance("RSA");

					// decode public key, FSTODO: convert to DER format
					X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(Base64.decode(tag.substring(2)));
					RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(pubSpec);

					// FSTODO: create test signature with privKey and test
					// validation with pubKey to check on a valid key pair
					System.out.println(pubKey);

				} catch (NoSuchAlgorithmException nsae) {
					throw new DkimException("RSA algorithm not found by JVM");
				} catch (IOException | InvalidKeySpecException ikse) {
					throw new DkimException("The public key " + tag + " in RR " + recordName + " couldn't be decoded.");
				}

				return true;
			}
		}

		throw new DkimException("No public key available in " + recordName);
	}

	private String getRecordName(String signingDomain, String selector) {
		return selector + "._domainkey." + signingDomain;
	}

	private String getValueFromDns(String recordName) {
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

	private Hashtable<String, String> getEnvironment() {
		Hashtable<String, String> environment = new Hashtable<String, String>();
		environment.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
		return environment;
	}

}
