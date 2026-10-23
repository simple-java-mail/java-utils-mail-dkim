package org.simplejavamail.utils.mail.dkim;

import jakarta.mail.MessagingException;
import net.markenwerk.utils.data.fetcher.BufferedDataFetcher;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.Enumeration;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Main class providing a signature according to DKIM RFC 4871.
 * 
 * @author Torsten Krause (tk at markenwerk dot net)
 * @author Florian Sager
 * @since 1.0.0
 */
public class DkimSigner {

   private static final Pattern SIGNING_DOMAIN_PATTERN = Pattern.compile("(.+)\\.(.+)");
   private static final Set<String> MANDATORY_HEADERS_TO_SIGN = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
   private static final Set<String> DEFAULT_HEADERS_TO_SIGN = DkimSigningEngine.defaultHeaders();
   static { MANDATORY_HEADERS_TO_SIGN.add("From"); }

   private final Set<String> headersToSign = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);

   private final String signingDomain;
   private final String selector;

   private final KeyPairType keyPairType;
   private final PrivateKey privateKey;

   private SigningAlgorithm signingAlgorithm;

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

      // Validate eagerly as before; retain no mutable cryptographic state.
      new SigningOperation(keyPairType, signingAlgorithm, privateKey);
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

   public void setCopyHeaderFields(boolean copyHeaderFields) {
      this.copyHeaderFields = copyHeaderFields;
   }

   /**
    * Returns whether the domain key should be retrieved and checked.
    * 
    * @return Whether the domain key should be retrieved and checked.
    * @see DomainKey#check(String, PrivateKey)
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
   protected String sign(final DkimMessage message) throws MessagingException {
      DkimSigningEngine.Settings settings = new DkimSigningEngine.Settings();
      settings.signingDomain = signingDomain;
      settings.selector = selector;
      settings.privateKey = privateKey;
      settings.keyPairType = keyPairType;
      settings.signingAlgorithm = signingAlgorithm;
      settings.headerCanonicalization = headerCanonicalization;
      settings.bodyCanonicalization = bodyCanonicalization;
      settings.canonicalizationNotation = getHeaderCanonicalization().getType() + "/" + getBodyCanonicalization().getType();
      settings.identity = identity;
      settings.lengthParam = lengthParam;
      settings.copyHeaderFields = copyHeaderFields;
      settings.checkDomainKey = checkDomainKey;
      settings.headersToSign.clear();
      settings.headersToSign.addAll(headersToSign);
      return DkimSigningEngine.sign(new DkimSigningEngine.Input() {
         public Enumeration<String> getSigningHeaderLines() throws MessagingException { return message.getSigningHeaderLines(); }
         public byte[] getEncodedBodyBytes() { return message.getEncodedBodyBytes(); }
         public Date getSentDate() throws MessagingException { return message.getSentDate(); }
      }, settings, true);
   }

}
