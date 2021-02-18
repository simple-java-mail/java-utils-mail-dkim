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

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.regex.Pattern;

import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

/**
 * A {@code DomainKey} holds the information about a domain key.
 * 
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
public final class DomainKey {

   private static final String DKIM_VERSION = "DKIM1";

   private static final String EMAIL_SERVICE_TYPE = "email";

   private final long timestamp;

   private final Pattern granularity;

   private final KeyPairType keyPairType;

   private final PublicKey publicKey;

   private final Set<String> serviceTypes;

   private final Map<Character, String> tags;

   /**
    * Creates a new {@code DomainKey} from the given tags.
    * 
    * @param tags The tags to be used.
    * @throws DkimException If either the version, key type or service type given
    *                       in the tags is incompatible to this library ('DKIM1',
    *                       'RSA' or 'Ed25519' and 'email' respectively).
    */
   public DomainKey(Map<Character, String> tags) throws DkimException {

      this.timestamp = System.currentTimeMillis();
      this.tags = Collections.unmodifiableMap(tags);

      String dkimVersionTagValue = getTagValue('v', DKIM_VERSION);
      if (!(DKIM_VERSION.equals(dkimVersionTagValue))) {
         throw new DkimException("Incompatible version v=" + getTagValue('v') + ".");
      }

      String granularityTagValue = getTagValue('g', "*");
      this.granularity = getGranularityPattern(granularityTagValue);

      String keyTypeTagValue = getTagValue('k', KeyPairType.RSA.getDkimNotation());
      this.keyPairType = getPublicKeyType(keyTypeTagValue);
      if (null == keyPairType) {
         throw new DkimException("Incompatible key type k=" + getTagValue('k') + ".");
      } else {
         keyPairType.initialize();
      }

      String serviceTypesTagValue = getTagValue('s', "*");
      serviceTypes = getServiceTypes(serviceTypesTagValue);
      if (!(serviceTypes.contains("*") || serviceTypes.contains(EMAIL_SERVICE_TYPE))) {
         throw new DkimException("Incompatible service type s=" + getTagValue('s') + ".");
      }

      String privateKeyTagValue = getTagValue('p');
      this.publicKey = getPublicKey(privateKeyTagValue);
      if (null == privateKeyTagValue) {
         throw new DkimException("Incompatible public key p=" + getTagValue('p') + ".");
      }

   }

   private KeyPairType getPublicKeyType(String keyTypeTagValue) {
      for (KeyPairType keyPairType : KeyPairType.values()) {
         if (keyPairType.getDkimNotation().equals(keyTypeTagValue)) {
            return keyPairType;
         }
      }
      return null;
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

   private PublicKey getPublicKey(String publicKeyTagValue) throws DkimException {
      if (null != publicKeyTagValue) {
         switch (keyPairType) {
            case RSA:
               return getRsaPublicKey(publicKeyTagValue);
            case ED25519:
               return getEd25519PublicKey(publicKeyTagValue);
            default:
               throw new DkimException("Unknown public key type " + keyPairType + ".");
         }
      } else {
         throw new DkimException("Missing public key value.");
      }
   }

   private RSAPublicKey getRsaPublicKey(String publicKeyTagValue) {
      try {
         KeyFactory keyFactory = KeyFactory.getInstance(KeyPairType.RSA.getJavaNotation());
         X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyTagValue));
         return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
      } catch (NoSuchAlgorithmException nsae) {
         throw new DkimException("RSA algorithm not found by JVM");
      } catch (IllegalArgumentException e) {
         throw new DkimException("The public key " + publicKeyTagValue + " couldn't be read.", e);
      } catch (InvalidKeySpecException e) {
         throw new DkimException("The public key " + publicKeyTagValue + " couldn't be decoded.", e);
      }
   }

   private EdDSAPublicKey getEd25519PublicKey(String publicKeyTagValue) {
      try {
         KeyFactory keyFactory = KeyFactory.getInstance(KeyPairType.ED25519.getJavaNotation());
         EdDSAPublicKeySpec publicKeySpec = new EdDSAPublicKeySpec(Base64.getDecoder().decode(publicKeyTagValue),
               EdDSANamedCurveTable.ED_25519_CURVE_SPEC);
         return (EdDSAPublicKey) keyFactory.generatePublic(publicKeySpec);
      } catch (NoSuchAlgorithmException nsae) {
         throw new DkimException("Ed25519 algorithm not found by JVM");
      } catch (IllegalArgumentException e) {
         throw new DkimException("The public key " + publicKeyTagValue + " couldn't be read.", e);
      } catch (InvalidKeySpecException e) {
         throw new DkimException("The public key " + publicKeyTagValue + " couldn't be decoded.", e);
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
    * Returns the type of public key of this {@code DomainKey}, as provided by the
    * 'p' tag.
    * 
    * @return The type of public key of this {@code DomainKey}.
    */
   public KeyPairType getPublicKeyType() {
      return keyPairType;
   }

   /**
    * Returns the public key of this {@code DomainKey}, as provided by the 'p' tag.
    * 
    * @return The public key of this {@code DomainKey}.
    */
   public PublicKey getPublicKey() {
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
      return "DomainKey [timestamp=" + timestamp + ", tags=" + tags + "]";
   }

   /**
    * Checks, whether this {@code DomainKey} fits to the given identity and
    * {@link RSAPrivateKey}.
    * 
    * @param identity   The identity.
    * @param privateKey The {@link RSAPrivateKey}.
    * @throws DkimSigningException If either the {@link DomainKey#getGranularity()
    *                              granularity} of this {@code DomainKey} doesn't
    *                              match the given identity or the
    *                              {@link DomainKey#getPublicKey() public key} of
    *                              this {@code DomainKey} doesn't belong to the
    *                              given {@link RSAPrivateKey}.
    */
   public void check(String identity, PrivateKey privateKey) throws DkimSigningException {
      checkIdentity(identity);
      checkKeyCompatiblilty(privateKey);
   }

   private void checkIdentity(String identity) throws DkimAcceptanceException {
      if (null != identity && !identity.contains("@")) {
         throw new DkimAcceptanceException("Invalid identity: " + identity);
      }
      String localPart = null == identity ? "" : identity.substring(0, identity.indexOf('@'));
      if (!granularity.matcher(localPart).matches()) {
         throw new DkimAcceptanceException("Incompatible identity for granularity "
               + getTagValue('g') + ": " + identity);
      }
   }

   private void checkKeyCompatiblilty(PrivateKey privateKey)
         throws DkimSigningException {

      try {

         SigningAlgorithm signingAlgorithm = keyPairType.getDefaultSigningAlgorithm();
         
         Signature signingSignature = Signature.getInstance(signingAlgorithm.getJavaNotation());
         signingSignature.initSign(privateKey);
         signingSignature.update("01189998819991197253".getBytes());
         byte[] signatureBytes = signingSignature.sign();

         Signature verifyingSignature = Signature.getInstance(signingAlgorithm.getJavaNotation());
         verifyingSignature.initVerify(publicKey);
         verifyingSignature.update("01189998819991197253".getBytes());

         if (!verifyingSignature.verify(signatureBytes)) {
            throw new DkimAcceptanceException("Incompatible private and public key.");
         }

      } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
         throw new DkimSigningException("Performing cryptography failed.", e);
      }

   }

}