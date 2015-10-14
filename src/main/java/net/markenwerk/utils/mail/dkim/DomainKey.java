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
 */
package net.markenwerk.utils.mail.dkim;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import net.iharder.Base64;

public final class DomainKey {

	private static final String RSA_MODE = "RSA/ECB/NoPadding";

	private final long timestamp;

	private final Pattern granularity;

	private final Set<String> serviceTypes;

	private final RSAPublicKey publicKey;

	private final Map<Character, String> tags;

	public DomainKey(Map<Character, String> tags) {
		timestamp = System.currentTimeMillis();
		this.tags = Collections.unmodifiableMap(tags);

		// version
		if (!("DKIM1".equals(getTagValue('v', "DKIM1")))) {
			throw new DkimException("Incompatible version v=" + getTagValue('v') + ".");
		}

		// granularity
		granularity = getGranularityPattern(getTagValue('g', "*"));

		// key type
		if (!("rsa".equals(getTagValue('k', "rsa")))) {
			throw new DkimException("Incompatible key type k=" + getTagValue('k') + ".");
		}

		// service type
		serviceTypes = getServiceTypes(getTagValue('s', "*"));
		if (!(serviceTypes.contains("*") || serviceTypes.contains("email"))) {
			throw new DkimException("Incompatible version v=" + getTagValue('v') + ".");
		}

		String privateKeyTagValue = getTagValue('p');
		if (null == privateKeyTagValue) {
			throw new DkimException("No public key available.");
		} else {
			publicKey = getPublicKey(privateKeyTagValue);
		}
	}

	private Set<String> getServiceTypes(String serviceTypesTagValue) {
		Set<String> serviceTypes = new HashSet<>();
		StringTokenizer tokenizer = new StringTokenizer(serviceTypesTagValue, ":", false);
		while (tokenizer.hasMoreElements()) {
			serviceTypes.add(tokenizer.nextToken().trim());
		}
		return serviceTypes;
	}

	private String getTagValue(char tag) {
		return getTagValue(tag, null);
	}

	private String getTagValue(char tag, String fallback) {
		String tagValue = tags.get(tag);
		return null == tagValue ? fallback : tagValue;
	}

	private RSAPublicKey getPublicKey(String privateKeyTagValue) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.decode(privateKeyTagValue));
			return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
		} catch (NoSuchAlgorithmException nsae) {
			throw new DkimException("RSA algorithm not found by JVM");
		} catch (IOException | InvalidKeySpecException ikse) {
			throw new DkimException("The public key " + privateKeyTagValue + " couldn't be decoded.");
		}
	}

	private Pattern getGranularityPattern(String granularity) {
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

	public long getTimestamp() {
		return timestamp;
	}

	public Pattern getGranularity() {
		return granularity;
	}

	public Set<String> getServiceTypes() {
		return serviceTypes;
	}

	public RSAPublicKey getPublicKey() {
		return publicKey;
	}

	public Map<Character, String> getTags() {
		return tags;
	}

	@Override
	public String toString() {
		return "Entry [timestamp=" + timestamp + ", tags=" + tags + "]";
	}

	public DkimAcceptance check(String from, RSAPrivateKey privateKey) throws DkimException {

		String localPart = from.substring(0, from.indexOf('@'));
		if (!granularity.matcher(localPart).matches()) {
			return DkimAcceptance.INCOMPATIBLE_GRANULARITY;
		}

		try {

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

}