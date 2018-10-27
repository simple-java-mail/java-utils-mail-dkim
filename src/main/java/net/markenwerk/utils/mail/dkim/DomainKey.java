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

/**
 * A {@code DomainKey} holds the information about a domain key.
 * 
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
public final class DomainKey {

	private static final String RSA_MODE = "RSA/ECB/NoPadding";

	private static final String DKIM_VERSION = "DKIM1";

	private static final String RSA_KEY_TYPE = "rsa";

	private static final String EMAIL_SERVICE_TYPE = "email";

	private final long timestamp;

	private final Pattern granularity;

	private final Set<String> serviceTypes;

	private final RSAPublicKey publicKey;

	private final Map<Character, String> tags;

	/**
	 * Creates a new {@code DomainKey} from the given tags.
	 * 
	 * @param tags
	 *            The tags to be used.
	 * @throws DkimException
	 *             If either the version, key type or service type given in the
	 *             tags is incompatible to this library ('DKIM1', 'RSA' and
	 *             'email' respectively).
	 */
	public DomainKey(Map<Character, String> tags) throws DkimException {
		timestamp = System.currentTimeMillis();
		this.tags = Collections.unmodifiableMap(tags);

		// version
		if (!(DKIM_VERSION.equals(getTagValue('v', DKIM_VERSION)))) {
			throw new DkimException("Incompatible version v=" + getTagValue('v') + ".");
		}

		// granularity
		granularity = getGranularityPattern(getTagValue('g', "*"));

		// key type
		if (!(RSA_KEY_TYPE.equals(getTagValue('k', RSA_KEY_TYPE)))) {
			throw new DkimException("Incompatible key type k=" + getTagValue('k') + ".");
		}

		// service type
		serviceTypes = getServiceTypes(getTagValue('s', "*"));
		if (!(serviceTypes.contains("*") || serviceTypes.contains(EMAIL_SERVICE_TYPE))) {
			throw new DkimException("Incompatible service type s=" + getTagValue('s') + ".");
		}

		String privateKeyTagValue = getTagValue('p');
		if (null == privateKeyTagValue) {
			throw new DkimException("No public key available.");
		} else {
			publicKey = getPublicKey(privateKeyTagValue);
		}
	}

	private Set<String> getServiceTypes(String serviceTypesTagValue) {
		Set<String> serviceTypes = new HashSet<String>();
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

	private RSAPublicKey getPublicKey(String privateKeyTagValue) throws DkimException {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.decode(privateKeyTagValue));
			return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
		} catch (NoSuchAlgorithmException nsae) {
			throw new DkimException("RSA algorithm not found by JVM");
		} catch (IOException e) {
			throw new DkimException("The public key " + privateKeyTagValue + " couldn't be read.");
		} catch (InvalidKeySpecException e) {
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

	/**
	 * Returns the construction time of this {@code DomainKey} as a timestamp.
	 * 
	 * @return The construction time of this {@code DomainKey} as a timestamp.
	 */
	public long getTimestamp() {
		return timestamp;
	}

	/**
	 * Returns a {@link Pattern} that matches the granularity of this
	 * {@code DomainKey}, as described in the 'g' tag.
	 * 
	 * @return A {@link Pattern} that matches the granularity of this
	 *         {@code DomainKey}.
	 */
	public Pattern getGranularity() {
		return granularity;
	}

	/**
	 * Returns the set of service types supported by this {@code DomainKey}, as
	 * described in the 's' tag.
	 * 
	 * @return The set of service types supported by this {@code DomainKey}.
	 */
	public Set<String> getServiceTypes() {
		return serviceTypes;
	}

	/**
	 * Returns the set of public key of this {@code DomainKey}, as provided by
	 * the 'p' tag.
	 * 
	 * @return The set of public key of this {@code DomainKey}.
	 */
	public RSAPublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Returns the {@link Collections#unmodifiableMap(Map) unmodifiable} map of
	 * tags, this {@code DomainKey} was constructed from.
	 * 
	 * @return The map of tags, this {@code DomainKey} was constructed from.
	 */
	public Map<Character, String> getTags() {
		return tags;
	}

	@Override
	public String toString() {
		return "Entry [timestamp=" + timestamp + ", tags=" + tags + "]";
	}

	/**
	 * Checks, whether this {@code DomainKey} fits to the given identity and
	 * {@link RSAPrivateKey}.
	 * 
	 * @param identity
	 *            The identity.
	 * @param privateKey
	 *            The {@link RSAPrivateKey}.
	 * @throws DkimSigningException
	 *             If either the {@link DomainKey#getGranularity() granularity}
	 *             of this {@code DomainKey} doesn't match the given identity or
	 *             the {@link DomainKey#getPublicKey() public key} of this
	 *             {@code DomainKey} doesn't belong to the given
	 *             {@link RSAPrivateKey}.
	 */
	public void check(String identity, RSAPrivateKey privateKey) throws DkimSigningException {

		String localPart = null == identity ? "" : identity.substring(0, identity.indexOf('@'));
		if (!granularity.matcher(localPart).matches()) {
			throw new DkimAcceptanceException("Incompatible identity (" + identity + ") for granularity g="
					+ getTagValue('g') + " ");
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

			if (!Arrays.equals(originalMessage, decryptedMessage)) {
				throw new DkimAcceptanceException("Incompatible private key for public key p=" + getTagValue('p') + " ");
			}

		} catch (NoSuchAlgorithmException e) {
			throw new DkimSigningException("No JCE provider supports " + RSA_MODE + " ciphers.", e);
		} catch (NoSuchPaddingException e) {
			throw new DkimSigningException("No JCE provider supports " + RSA_MODE + " ciphers.", e);
		} catch (InvalidKeyException e) {
			throw new DkimSigningException("Performing RSA cryptography failed.", e);
		} catch (IllegalBlockSizeException e) {
			throw new DkimSigningException("Performing RSA cryptography failed.", e);
		} catch (BadPaddingException e) {
			throw new DkimSigningException("Performing RSA cryptography failed.", e);
		}
	}
}