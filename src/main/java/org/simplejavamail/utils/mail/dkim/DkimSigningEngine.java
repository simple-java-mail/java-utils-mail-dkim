package org.simplejavamail.utils.mail.dkim;

import jakarta.mail.Header;
import jakarta.mail.MessagingException;
import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.Map.Entry;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.charset.StandardCharsets.ISO_8859_1;

/** The one DKIM engine, independent of message wrappers and mail providers. */
final class DkimSigningEngine {
   private static final int MAX_HEADER_LENGTH = 67;

   private static final String DKIM_SIGNATUR_HEADER = "DKIM-Signature";


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


   interface Input {
      Enumeration<String> getSigningHeaderLines() throws MessagingException;
      byte[] getEncodedBodyBytes() throws DkimSigningException;
      Date getSentDate() throws MessagingException;
   }

   static final class Settings {
      String signingDomain;
      String selector;
      PrivateKey privateKey;
      KeyPairType keyPairType;
      SigningAlgorithm signingAlgorithm = SigningAlgorithm.SHA256_WITH_RSA;
      Canonicalization headerCanonicalization = Canonicalization.RELAXED;
      Canonicalization bodyCanonicalization = Canonicalization.SIMPLE;
      String canonicalizationNotation;
      String identity;
      boolean lengthParam;
      boolean copyHeaderFields;
      boolean checkDomainKey = true;
      final Set<String> headersToSign = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);

      Settings() { headersToSign.addAll(DEFAULT_HEADERS_TO_SIGN); }

      Settings copy() {
         Settings result = new Settings();
         result.signingDomain = signingDomain;
         result.selector = selector;
         result.privateKey = privateKey;
         result.keyPairType = keyPairType;
         result.signingAlgorithm = signingAlgorithm;
         result.headerCanonicalization = headerCanonicalization;
         result.bodyCanonicalization = bodyCanonicalization;
         result.canonicalizationNotation = canonicalizationNotation;
         result.identity = identity;
         result.lengthParam = lengthParam;
         result.copyHeaderFields = copyHeaderFields;
         result.checkDomainKey = checkDomainKey;
         result.headersToSign.clear();
         result.headersToSign.addAll(headersToSign);
         return result;
      }
   }

   static Set<String> defaultHeaders() { return Collections.unmodifiableSet(DEFAULT_HEADERS_TO_SIGN); }

   static String sign(Input input, Settings settings, boolean legacy) throws MessagingException {
      return new DkimSigningEngine(settings, legacy).sign(input);
   }

   private final String signingDomain;
   private final String selector;
   private final PrivateKey privateKey;
   private final KeyPairType keyPairType;
   private final SigningAlgorithm signingAlgorithm;
   private final Canonicalization headerCanonicalization;
   private final Canonicalization bodyCanonicalization;
   private final String canonicalizationNotation;
   private final String identity;
   private final boolean lengthParam;
   private final boolean copyHeaderFields;
   private final boolean checkDomainKey;
   private final Set<String> headersToSign;
   private final boolean legacy;

   private DkimSigningEngine(Settings settings, boolean legacy) {
      this.signingDomain = settings.signingDomain;
      this.selector = settings.selector;
      this.privateKey = settings.privateKey;
      this.keyPairType = settings.keyPairType;
      this.signingAlgorithm = settings.signingAlgorithm;
      this.headerCanonicalization = settings.headerCanonicalization;
      this.bodyCanonicalization = settings.bodyCanonicalization;
      this.canonicalizationNotation = settings.canonicalizationNotation != null ? settings.canonicalizationNotation
            : headerCanonicalization.getType() + "/" + bodyCanonicalization.getType();
      this.identity = settings.identity;
      this.lengthParam = settings.lengthParam;
      this.copyHeaderFields = settings.copyHeaderFields;
      this.checkDomainKey = settings.checkDomainKey;
      this.headersToSign = settings.headersToSign;
      this.legacy = legacy;
   }

   private String sign(Input message) throws MessagingException {

      SigningOperation operation = new SigningOperation(keyPairType, signingAlgorithm, privateKey, legacy);

      if (checkDomainKey) {
         checkDomainKey();
      }

      Map<String, String> signatureData = new LinkedHashMap<String, String>();
      signatureData.put("v", "1");
      signatureData.put("a", signingAlgorithm.getDkimNotation());
      signatureData.put("q", "dns/txt");
      signatureData.put("c", canonicalizationNotation);
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

      for (String headerLine : compileHeadersToSign(message)) {
         Header header = new Header(headerLine.substring(0, headerLine.indexOf(':')).trim(),
               headerLine.substring(headerLine.indexOf(':') + 1));
         String headerName = header.getName();
         String headerValue = header.getValue();
         headerNames.append(headerName).append(":");
         headerValues.append(headerCanonicalization == Canonicalization.SIMPLE ? headerLine
               : headerCanonicalization.canonicalizeHeader(headerName, headerValue));
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

      byte[] canonicalBody = canonicalizeBody(message);
      if (lengthParam) {
         signatureData.put("l", Integer.toString(canonicalBody.length));
      }
      signatureData.put("bh", base64Encode(operation.digest(canonicalBody)));

      String serializedSignature = serializeSignature(signatureData);
      headerValues.append(headerCanonicalization.canonicalizeHeader(DKIM_SIGNATUR_HEADER, serializedSignature));
      byte[] signature = operation.sign(headerBytes(headerValues.toString()));

      return DKIM_SIGNATUR_HEADER + ": " + serializedSignature + fold(base64Encode(signature), 3);

   }

   private void checkDomainKey() throws DkimSigningException {
      try {
         (legacy ? DomainKeyUtil.getDomainKey(signingDomain, selector)
               : DomainKeyUtil.getDomainKeyForByteSigning(signingDomain, selector)).check(identity, privateKey);
      } catch (DkimException e) {
         throw new DkimSigningException("Failed to obtain the domain key for " + signingDomain + "." + selector, e);
      }
   }

   private Date getSentDate(Input message) throws MessagingException {
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

   private List<String> compileHeadersToSign(Input message) throws DkimSigningException {
      List<String> reverseOrderHeaderLines = new LinkedList<String>();
      try {
         Enumeration<String> lines = message.getSigningHeaderLines();
         while (lines.hasMoreElements()) {
            String line = lines.nextElement();
            int colon = line.indexOf(':');
            if (colon >= 0 && headersToSign.contains(line.substring(0, colon).trim())) {
               reverseOrderHeaderLines.add(0, line);
            }
         }
      } catch (MessagingException e) {
         throw new DkimSigningException("Could not retrieve the header fields for signing", e);
      }
      return reverseOrderHeaderLines;
   }

   private byte[] canonicalizeBody(Input message) throws DkimSigningException {
      byte[] bodyBytes = normalizeCrLf(message.getEncodedBodyBytes());
      return bodyCanonicalization.canonicalizeBody(new String(bodyBytes, ISO_8859_1)).getBytes(ISO_8859_1);
   }

   private static byte[] normalizeCrLf(byte[] bytes) {
      ByteArrayOutputStream output = new ByteArrayOutputStream(bytes.length);
      int previous = -1;
      for (byte value : bytes) {
         int current = value & 0xff;
         if (current == '\r') {
            output.write('\r');
            output.write('\n');
         } else if (current == '\n') {
            if (previous != '\r') {
               output.write('\r');
               output.write('\n');
            }
         } else {
            output.write(current);
         }
         previous = current;
      }
      return output.toByteArray();
   }

   private static byte[] headerBytes(String value) {
      byte[] bytes = new byte[value.length()];
      for (int i = 0; i < bytes.length; i++) {
         bytes[i] = (byte) value.charAt(i);
      }
      return bytes;
   }

   private String serializeSignature(Map<String, String> signatureData) {
      if (!legacy) {
         return SignatureHeaderFormatter.serializeTags(signatureData);
      }

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

   private String fold(String string, int offset) {
      if (!legacy) {
         return SignatureHeaderFormatter.fold(string, offset);
      }

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

   private static String quotedPrintable(String s) {
      StringBuilder encoded = new StringBuilder();
      String hex = "0123456789ABCDEF";
      int column = 0;
      for (byte value : s.getBytes(UTF_8)) {
         int octet = value & 0xff;
         boolean literal = octet > 32 && octet < 127 && octet != '=' && octet != ';';
         int length = literal ? 1 : 3;
         if (column + length > MAX_HEADER_LENGTH) {
            // DKIM uses folding whitespace, never MIME's '=CRLF' soft breaks.
            encoded.append("\r\n\t");
            column = 1;
         }
         if (literal) {
            encoded.append((char) octet);
         } else {
            encoded.append('=').append(hex.charAt(octet >>> 4)).append(hex.charAt(octet & 15));
         }
         column += length;
      }
      return encoded.toString();
   }

   private static String base64Encode(byte[] bytes) {
      String encoded = Base64.getEncoder().encodeToString(bytes);

      // remove unnecessary line feeds after 76 characters
      encoded = encoded.replace("\n", "");
      encoded = encoded.replace("\r", "");

      return encoded;
   }

}
