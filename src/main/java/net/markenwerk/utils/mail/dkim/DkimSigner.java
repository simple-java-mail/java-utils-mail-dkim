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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

import jakarta.mail.Header;
import jakarta.mail.MessagingException;

import com.sun.mail.util.CRLFOutputStream;
import com.sun.mail.util.QPEncoderStream;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.markenwerk.utils.data.fetcher.BufferedDataFetcher;
import net.markenwerk.utils.data.fetcher.DataFetchException;

/**
 * Main class providing a signature according to DKIM RFC 4871.
 * 
 * @author Torsten Krause (tk at markenwerk dot net)
 * @author Florian Sager
 * @since 1.0.0
 */
public class DkimSigner {

   private static final int MAX_HEADER_LENGTH = 67;

   private static final String DKIM_SIGNATUR_HEADER = "DKIM-Signature";

   private static final Pattern SIGNING_DOMAIN_PATTERN = Pattern.compile("(.+)\\.(.+)");

   private static final Set<String> MANDATORY_HEADERS_TO_SIGN = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);

   private static final Set<String> DEFAULT_HEADERS_TO_SIGN = new HashSet<String>();

   static {

      MANDATORY_HEADERS_TO_SIGN.add("From");

      DEFAULT_HEADERS_TO_SIGN.addAll(MANDATORY_HEADERS_TO_SIGN);
      DEFAULT_HEADERS_TO_SIGN.add("To");
      DEFAULT_HEADERS_TO_SIGN.add("Subject");
      DEFAULT_HEADERS_TO_SIGN.add("Content-Description");
      DEFAULT_HEADERS_TO_SIGN.add("Content-ID");
      DEFAULT_HEADERS_TO_SIGN.add("Content-Type");
      DEFAULT_HEADERS_TO_SIGN.add("Content-Transfer-Encoding");
      DEFAULT_HEADERS_TO_SIGN.add("Cc");
      DEFAULT_HEADERS_TO_SIGN.add("Date");
      DEFAULT_HEADERS_TO_SIGN.add("In-Reply-To");
      DEFAULT_HEADERS_TO_SIGN.add("List-Subscribe");
      DEFAULT_HEADERS_TO_SIGN.add("List-Post");
      DEFAULT_HEADERS_TO_SIGN.add("List-Owner");
      DEFAULT_HEADERS_TO_SIGN.add("List-Id");
      DEFAULT_HEADERS_TO_SIGN.add("List-Archive");
      DEFAULT_HEADERS_TO_SIGN.add("List-Help");
      DEFAULT_HEADERS_TO_SIGN.add("List-Unsubscribe");
      DEFAULT_HEADERS_TO_SIGN.add("MIME-Version");
      DEFAULT_HEADERS_TO_SIGN.add("Message-ID");
      DEFAULT_HEADERS_TO_SIGN.add("Resent-Sender");
      DEFAULT_HEADERS_TO_SIGN.add("Resent-Cc");
      DEFAULT_HEADERS_TO_SIGN.add("Resent-Date");
      DEFAULT_HEADERS_TO_SIGN.add("Resent-To");
      DEFAULT_HEADERS_TO_SIGN.add("Reply-To");
      DEFAULT_HEADERS_TO_SIGN.add("References");
      DEFAULT_HEADERS_TO_SIGN.add("Resent-Message-ID");
      DEFAULT_HEADERS_TO_SIGN.add("Resent-From");
      DEFAULT_HEADERS_TO_SIGN.add("Sender");

   }

   private final Set<String> headersToSign = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);

   private final String signingDomain;
   private final String selector;

   private final KeyPairType keyPairType;
   private final PrivateKey privateKey;

   private SigningAlgorithm signingAlgorithm;
   private MessageDigest messageDigest;
   private Signature signature;

   private Canonicalization headerCanonicalization;
   private Canonicalization bodyCanonicalization;

   private String identity;
   private boolean lengthParam;
   private boolean copyHeaderFields;

   private boolean checkDomainKey;

   /**
    * Created a new {@code DkimSigner} for the given signing domain and selector
    * with the given DER encoded RSA private Key.
    *
    * @param signingDomain The signing domain to be used.
    * @param selector      The selector to be used.
    * @param derFile       A {@link File} that contains the DER encoded RSA private
    *                      key to be used.
    * 
    * @throws IOException              If reading the content of the given
    *                                  {@link File} failed.
    * @throws NoSuchAlgorithmException If the RSA algorithm is not supported.
    * @throws InvalidKeySpecException  If the content of the given {@link File}
    *                                  couldn't be interpreted as an RSA private
    *                                  key.
    * @throws DkimException            If the given signing domain is invalid.
    */
   public DkimSigner(String signingDomain, String selector, File derFile)
         throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, DkimException {
      this(signingDomain, selector, new FileInputStream(derFile));
   }

   /**
    * Created a new {@code DkimSigner} for the given signing domain and selector
    * with the given DER encoded RSA private Key.
    * 
    * @param signingDomain The signing domain to be used.
    * @param selector      The selector to be used.
    * @param derStream     A {@link InputStream} that yields the DER encoded RSA
    *                      private key to be used. The {@link InputStream} will be
    *                      closed after it has been read.
    * 
    * @throws IOException              If reading the content of the given
    *                                  {@link InputStream} failed.
    * @throws NoSuchAlgorithmException If the RSA algorithm is not supported.
    * @throws InvalidKeySpecException  If the content of the given
    *                                  {@link InputStream} couldn't be interpreted
    *                                  as an RSA private key.
    * @throws DkimException            If the given signing domain is invalid.
    */
   public DkimSigner(String signingDomain, String selector, InputStream derStream)
         throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
      this(signingDomain, selector, readPrivateKey(derStream));
   }

   private static RSAPrivateKey readPrivateKey(InputStream derStream)
         throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
      byte[] privKeyBytes = new BufferedDataFetcher().fetch(derStream, true);
      KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
      PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privKeyBytes);
      return (RSAPrivateKey) rsaKeyFactory.generatePrivate(privateKeySpec);
   }

   /**
    * Created a new {@code DkimSigner} for the given signing domain and selector
    * with the given {@link RSAPrivateKey}.
    * 
    * @param signingDomain The signing domain to be used.
    * @param selector      The selector to be used.
    * @param privateKey    The {@link RSAPrivateKey} to be used to sign
    *                      {@link DkimMessage DkimMessage}s.
    * @throws DkimException If the given signing domain is invalid.
    */
   public DkimSigner(String signingDomain, String selector, RSAPrivateKey privateKey) throws DkimException {
      checkSigningDomain(signingDomain);
      this.headersToSign.addAll(DEFAULT_HEADERS_TO_SIGN);
      this.signingDomain = signingDomain;
      this.selector = selector.trim();
      this.keyPairType = KeyPairType.RSA;
      this.privateKey = privateKey;
      setSigningAlgorithm(keyPairType.getDefaultSigningAlgorithm());
      setHeaderCanonicalization(Canonicalization.RELAXED);
      setBodyCanonicalization(Canonicalization.SIMPLE);
      setCheckDomainKey(true);
   }

   /**
    * Created a new {@code DkimSigner} for the given signing domain and selector
    * with the given {@link RSAPrivateKey}.
    * 
    * @param signingDomain The signing domain to be used.
    * @param selector      The selector to be used.
    * @param privateKey    The {@link RSAPrivateKey} to be used to sign
    *                      {@link DkimMessage DkimMessage}s.
    * @throws DkimException If the given signing domain is invalid.
    */
   public DkimSigner(String signingDomain, String selector, EdDSAPrivateKey privateKey) throws DkimException {
      checkSigningDomain(signingDomain);
      this.headersToSign.addAll(DEFAULT_HEADERS_TO_SIGN);
      this.signingDomain = signingDomain;
      this.selector = selector.trim();
      this.keyPairType = KeyPairType.ED25519;
      this.privateKey = privateKey;
      keyPairType.initialize();
      setSigningAlgorithm(keyPairType.getDefaultSigningAlgorithm());
      setHeaderCanonicalization(Canonicalization.RELAXED);
      setBodyCanonicalization(Canonicalization.SIMPLE);
      setCheckDomainKey(true);
   }

   private void checkSigningDomain(String signingDomain) {
      if (null == signingDomain || !SIGNING_DOMAIN_PATTERN.matcher(signingDomain).matches()) {
         throw new DkimException(signingDomain + " is an invalid signing domain");
      }
   }

   /**
    * Adds a header to the set of headers that will be included in the signature,
    * if present.
    * 
    * @param header The name of the header.
    */
   public void addHeaderToSign(String header) {
      if (null != header && 0 != header.length()) {
         headersToSign.add(header);
      }
   }

   /**
    * Removes a header from the set of headers that will be included in the
    * signature, unless it is one of the required headers ('From', 'To',
    * 'Subject').
    * 
    * @param header The name of the header.
    */
   public void removeHeaderToSign(String header) {
      if (null != header && 0 != header.length() && !isMandatoryHeader(header)) {
         headersToSign.remove(header);
      }
   }

   private static boolean isMandatoryHeader(String header) {
      return MANDATORY_HEADERS_TO_SIGN.contains(header);
   }

   /**
    * Returns the configured {@link SigningAlgorithm}.
    * 
    * @return The configured {@link SigningAlgorithm}.
    */
   public SigningAlgorithm getSigningAlgorithm() {
      return signingAlgorithm;
   }

   /**
    * Sets the {@link SigningAlgorithm} to be used.
    * 
    * @param signingAlgorithm The {@link SigningAlgorithm} to be used.
    * 
    * @throws DkimException If either the signing algorithm or the hashing
    *                       algorithm is not supported or the {@link Signature}
    *                       couldn't be initialized.
    */
   public void setSigningAlgorithm(SigningAlgorithm signingAlgorithm) throws DkimException {

      if (!keyPairType.supportsSigningAlgorithm(signingAlgorithm)) {
         throw new DkimException("Unsupported signing algorithm: " + signingAlgorithm);
      }

      try {
         messageDigest = MessageDigest.getInstance(signingAlgorithm.getHashNotation());
      } catch (NoSuchAlgorithmException e) {
         throw new DkimException("Unknown hashing algorithm: " + signingAlgorithm.getHashNotation(), e);
      }

      try {
         signature = Signature.getInstance(signingAlgorithm.getJavaNotation());
         signature.initSign(privateKey);
      } catch (NoSuchAlgorithmException e) {
         throw new DkimException("Unknown signing algorithm " + signingAlgorithm.getJavaNotation(), e);
      } catch (InvalidKeyException e) {
         throw new DkimException("Invalid private key", e);
      }

      this.signingAlgorithm = signingAlgorithm;

   }

   /**
    * Returns the configured {@link Canonicalization} to be used for the headers.
    * 
    * @return The configured {@link Canonicalization} to be used for the headers.
    */
   public Canonicalization getHeaderCanonicalization() {
      return headerCanonicalization;
   }

   /**
    * Sets the {@link Canonicalization} to be used for the headers.
    * 
    * @param canonicalization The {@link Canonicalization} to be used for the
    *                         headers.
    */
   public void setHeaderCanonicalization(Canonicalization canonicalization) {
      this.headerCanonicalization = canonicalization;
   }

   /**
    * Returns the configured {@link Canonicalization} to be used for the body.
    * 
    * @return The configured {@link Canonicalization} to be used for the body.
    */
   public Canonicalization getBodyCanonicalization() {
      return bodyCanonicalization;
   }

   /**
    * Sets the {@link Canonicalization} to be used for the body.
    * 
    * @param canonicalization The {@link Canonicalization} to be used for the body.
    */
   public void setBodyCanonicalization(Canonicalization canonicalization) {
      this.bodyCanonicalization = canonicalization;
   }

   /**
    * Returns the configured identity parameter.
    * 
    * @return The configured identity parameter.
    */
   public String getIdentity() {
      return identity;
   }

   /**
    * Sets the identity parameter to be used.
    * 
    * @param identity The identity to be used.
    * @throws DkimException If the given identity parameter isn't the signing
    *                       domain of this {@code DkimSigner} or an subdomain
    *                       thereof.
    */
   public void setIdentity(String identity) throws DkimException {
      if (null != identity) {
         checkIdentity(identity);
      }
      this.identity = identity;
   }

   private void checkIdentity(String identity) {
      if (!identity.endsWith("@" + signingDomain) && !identity.endsWith("." + signingDomain)) {
         throw new DkimException(
               "The domain part of " + identity + " isn't " + signingDomain + " or a subdomain thereof");
      }
   }

   /**
    * Returns the configured length parameter.
    * 
    * @return The configured length parameter.
    */
   public boolean getLengthParam() {
      return lengthParam;
   }

   /**
    * Sets the length parameter to be used.
    * 
    * @param lengthParam The length parameter to be used.
    */
   public void setLengthParam(boolean lengthParam) {
      this.lengthParam = lengthParam;
   }

   /**
    * Returns the configured z parameter.
    * 
    * @return The configured z parameter.
    * 
    * @deprecated Use {@link DkimSigner#isCopyHeaderFields()} instead.
    */
   @Deprecated
   public boolean isZParam() {
      return isCopyHeaderFields();
   }

   /**
    * Sets the z parameter to be used.
    * 
    * @param zParam The z parameter to be used.
    * 
    * @deprecated Use {@link DkimSigner#setCopyHeaderFields(boolean)} instead.
    */
   @Deprecated
   public void setZParam(boolean zParam) {
      setCopyHeaderFields(zParam);
   }

   /**
    * Returns the configured z parameter.
    * 
    * @return The configured z parameter.
    */
   public boolean isCopyHeaderFields() {
      return copyHeaderFields;
   }

   /**
    * Sets the z parameter to be used.
    * 
    * @param zParam The z parameter to be used.
    */
   public void setCopyHeaderFields(boolean copyHeaderFields) {
      this.copyHeaderFields = copyHeaderFields;
   }

   /**
    * Returns whether the domain key should be retrieved and checked.
    * 
    * @return Whether the domain key should be retrieved and checked.
    * @see DomainKey#check(String, RSAPrivateKey)
    */
   public boolean isCheckDomainKey() {
      return checkDomainKey;
   }

   /**
    * Sets, whether the domain key should be retrieved and checked.
    * 
    * @param checkDomainKey Whether the domain key should be retrieved and checked.
    */
   public void setCheckDomainKey(boolean checkDomainKey) {
      this.checkDomainKey = checkDomainKey;
   }

   /**
    * Returns the DKIM signature header line.
    * 
    * @param message The {@link DkimMessage} to sign.
    * @return The DKIM signature header line
    * @throws DkimSigningException If the {@link DkimMessage} couldn't be signed.
    */
   protected String sign(DkimMessage message) throws MessagingException {

      if (checkDomainKey) {
         checkDomainKey();
      }

      Map<String, String> signatureData = new LinkedHashMap<String, String>();
      signatureData.put("v", "1");
      signatureData.put("a", signingAlgorithm.getDkimNotation());
      signatureData.put("q", "dns/txt");
      signatureData.put("c", getHeaderCanonicalization().getType() + "/" + getBodyCanonicalization().getType());
      signatureData.put("t", Long.toString(getSentDate(message).getTime() / 1000l));
      signatureData.put("s", selector);
      signatureData.put("d", signingDomain);

      if (null != identity) {
         signatureData.put("i", quotedPrintable(identity));
      }

      StringBuilder headerNames = new StringBuilder();
      StringBuilder headerValues = new StringBuilder();
      StringBuilder headerFieldCopy = new StringBuilder();
      Set<String> mandatoryHeaders = compileMandatoryHeaders();

      for (Header header : compileHeadersToSign(message)) {
         String headerName = header.getName();
         String headerValue = header.getValue();
         headerNames.append(headerName).append(":");
         headerValues.append(headerCanonicalization.canonicalizeHeader(headerName, headerValue));
         headerValues.append("\r\n");
         mandatoryHeaders.remove(headerName);
         if (copyHeaderFields) {
            headerFieldCopy.append(headerName);
            headerFieldCopy.append(":");
            headerFieldCopy.append(quotedPrintable(headerValue.trim()).replace("|", "=7C"));
            headerFieldCopy.append("|");
         }
      }

      if (!mandatoryHeaders.isEmpty()) {
         throw new DkimSigningException("Could not find mandatory headers: " + join(mandatoryHeaders, ", "));
      }

      signatureData.put("h", headerNames.substring(0, headerNames.length() - 1));
      if (copyHeaderFields) {
         signatureData.put("z", headerFieldCopy.substring(0, headerFieldCopy.length() - 1));
      }

      String canonicalBody = canonicalizeBody(message);
      if (lengthParam) {
         signatureData.put("l", Integer.toString(canonicalBody.length()));
      }
      signatureData.put("bh", base64Encode(messageDigest.digest(canonicalBody.getBytes())));

      String serializedSignature = serializeSignature(signatureData);
      headerValues.append(headerCanonicalization.canonicalizeHeader(DKIM_SIGNATUR_HEADER, serializedSignature));
      byte[] signature = createSignature(headerValues.toString().getBytes());

      return DKIM_SIGNATUR_HEADER + ": " + serializedSignature + fold(base64Encode(signature), 3);

   }

   private void checkDomainKey() throws DkimSigningException {
      try {
         DomainKeyUtil.getDomainKey(signingDomain, selector).check(identity, privateKey);
      } catch (DkimException e) {
         throw new DkimSigningException("Failed to obtain the domain key for " + signingDomain + "." + selector, e);
      }
   }

   private Date getSentDate(DkimMessage message) throws MessagingException {
      Date sentDate = message.getSentDate();
      if (null == sentDate) {
         sentDate = new Date();
      }
      return sentDate;
   }

   private Set<String> compileMandatoryHeaders() {
      Set<String> mandatoryHeaders = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
      mandatoryHeaders.addAll(MANDATORY_HEADERS_TO_SIGN);
      return mandatoryHeaders;
   }

   private List<Header> compileHeadersToSign(DkimMessage message) throws DkimSigningException {
      List<Header> reverseOrderHeaderLines = new LinkedList<Header>();
      for (Header header : getMessageHeaders(message)) {
         if (headersToSign.contains(header.getName())) {
            reverseOrderHeaderLines.add(0, header);
         }
      }
      return reverseOrderHeaderLines;
   }

   private Iterable<Header> getMessageHeaders(DkimMessage message) throws DkimSigningException {
      try {
         return headerIterable(message.getAllHeaders());
      } catch (MessagingException e) {
         throw new DkimSigningException("Could not retrieve the header fields for signing", e);
      }
   }

   private Iterable<Header> headerIterable(final Enumeration<Header> headers) throws MessagingException {
      return new Iterable<Header>() {

         @Override
         public Iterator<Header> iterator() {
            return headerIterator(headers);
         }

      };
   }

   private Iterator<Header> headerIterator(final Enumeration<Header> headers) {
      return new Iterator<Header>() {

         @Override
         public boolean hasNext() {
            return headers.hasMoreElements();
         }

         @Override
         public Header next() {
            return headers.nextElement();
         }

      };
   }

   private String canonicalizeBody(DkimMessage message) throws DkimSigningException {
      try {
         byte[] bodyBytes = message.getEncodedBody().getBytes();
         ByteArrayOutputStream buffer = new ByteArrayOutputStream();
         new BufferedDataFetcher().copy(new ByteArrayInputStream(bodyBytes), new CRLFOutputStream(buffer));
         return bodyCanonicalization.canonicalizeBody(buffer.toString());
      } catch (DataFetchException e) {
         throw new DkimSigningException("Failed to canonicalize the line terminators of the message body", e);
      }
   }

   private String serializeSignature(Map<String, String> signatureData) {

      int position = 0;
      StringBuilder builder = new StringBuilder();

      for (Entry<String, String> entry : signatureData.entrySet()) {

         StringBuilder entryBuilder = new StringBuilder();
         entryBuilder.append(entry.getKey()).append("=").append(entry.getValue()).append(";");

         if (position + entryBuilder.length() + 1 > MAX_HEADER_LENGTH) {
            position = entryBuilder.length();
            builder.append("\r\n\t").append(entryBuilder);
         } else {
            builder.append(" ").append(entryBuilder);
            position += 1 + entryBuilder.length();
         }

      }

      builder.append("\r\n\tb=");
      return builder.toString().trim();

   }

   private byte[] createSignature(byte[] bytes) throws DkimSigningException {
      try {
         signature.update(bytes);
         return signature.sign();
      } catch (SignatureException e) {
         throw new DkimSigningException("Faild to create signature", e);
      }
   }

   private static String fold(String string, int offset) {

      int i = 0;
      StringBuilder builder = new StringBuilder();

      while (true) {
         if (offset > 0 && string.substring(i).length() > MAX_HEADER_LENGTH - offset) {
            builder.append(string.substring(i, i + MAX_HEADER_LENGTH - offset));
            i += MAX_HEADER_LENGTH - offset;
            offset = 0;
         } else if (string.substring(i).length() > MAX_HEADER_LENGTH) {
            builder.append("\r\n\t").append(string.substring(i, i + MAX_HEADER_LENGTH));
            i += MAX_HEADER_LENGTH;
         } else {
            builder.append("\r\n\t").append(string.substring(i));
            break;
         }
      }

      return builder.toString();
   }

   private static String join(Collection<String> values, String separator) {
      StringBuilder builder = new StringBuilder();
      for (String value : values) {
         builder.append(value);
         builder.append(separator);
      }
      return builder.substring(0, builder.length() - separator.length());
   }

   // FSTODO: converts to "platforms default encoding" might be wrong ?
   private static String quotedPrintable(String s) {
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

   private static String base64Encode(byte[] bytes) {
      String encoded = Base64.getEncoder().encodeToString(bytes);

      // remove unnecessary line feeds after 76 characters
      encoded = encoded.replace("\n", "");
      encoded = encoded.replace("\r", "");

      return encoded;
   }

}
