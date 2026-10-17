package org.simplejavamail.utils.mail.dkim;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DomainKeyValidationTest {

   // Published test keys from RFC 8463, Appendix A; never production material.
   private static final String ED25519_PUBLIC = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
   private static final String ED25519_SECRET = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";

   private static KeyPair rsaKeyPair;
   private static KeyPair otherRsaKeyPair;

   @BeforeAll
   static void createKeys() throws Exception {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(1024);
      rsaKeyPair = generator.generateKeyPair();
      otherRsaKeyPair = generator.generateKeyPair();
   }

   @Test
   void defaultsToDkim1RsaWildcardServiceAndGranularity() {
      DomainKey domainKey = new DomainKey(rsaTags());

      assertThat(domainKey.getPublicKeyType()).isEqualTo(KeyPairType.RSA);
      assertThat(domainKey.getServiceTypes()).containsExactly("*");
      assertThat(domainKey.getGranularity().matcher("any.local+part").matches()).isTrue();
      assertThat(domainKey.getTimestamp()).isPositive();
   }

   @Test
   void checksMatchingRsaKeys() {
      assertThatCode(() -> new DomainKey(rsaTags()).check("person@example.com", rsaKeyPair.getPrivate()))
            .doesNotThrowAnyException();
   }

   @Test
   void rejectsDifferentRsaKeyWithAcceptanceException() {
      assertThatThrownBy(() -> new DomainKey(rsaTags()).check(null, otherRsaKeyPair.getPrivate()))
            .isInstanceOf(DkimAcceptanceException.class).hasMessage("Incompatible private and public key.");
   }

   @Test
   void quotesRegexMetacharactersInGranularity() {
      Map<Character, String> tags = rsaTags();
      tags.put('g', "user.+*");
      DomainKey domainKey = new DomainKey(tags);

      assertThatCode(() -> domainKey.check("user.+suffix@example.com", rsaKeyPair.getPrivate())).doesNotThrowAnyException();
      assertThatThrownBy(() -> domainKey.check("userXsuffix@example.com", rsaKeyPair.getPrivate()))
            .isInstanceOf(DkimAcceptanceException.class).hasMessageContaining("Incompatible identity");
   }

   @Test
   void treatsAbsentIdentityAsEmptyLocalPart() {
      Map<Character, String> tags = rsaTags();
      tags.put('g', "");

      assertThatCode(() -> new DomainKey(tags).check(null, rsaKeyPair.getPrivate())).doesNotThrowAnyException();
      assertThatThrownBy(() -> new DomainKey(tags).check("user@example.com", rsaKeyPair.getPrivate()))
            .isInstanceOf(DkimAcceptanceException.class);
   }

   @Test
   void rejectsIdentityWithoutDomainSeparator() {
      assertThatThrownBy(() -> new DomainKey(rsaTags()).check("invalid", rsaKeyPair.getPrivate()))
            .isInstanceOf(DkimAcceptanceException.class).hasMessage("Invalid identity: invalid");
   }

   @Test
   void acceptsEmailAmongOtherServiceTypes() {
      Map<Character, String> tags = rsaTags();
      tags.put('s', "other : email : another");

      assertThat(new DomainKey(tags).getServiceTypes()).containsExactlyInAnyOrder("other", "email", "another");
   }

   @Test
   void rejectsUnsupportedVersionKeyTypeAndService() {
      for (char tag : new char[] { 'v', 'k', 's' }) {
         Map<Character, String> tags = rsaTags();
         tags.put(tag, "unsupported");
         assertThatThrownBy(() -> new DomainKey(tags)).isInstanceOf(DkimException.class)
               .hasMessageContaining("Incompatible");
      }
   }

   @Test
   void rejectsMissingRevokedAndMalformedPublicKeys() {
      Map<Character, String> missing = new HashMap<Character, String>();
      assertThatThrownBy(() -> new DomainKey(missing)).isInstanceOf(DkimException.class)
            .hasMessage("Missing public key value.");
      for (String value : new String[] { "", "%%%", "YWJj" }) {
         Map<Character, String> tags = rsaTags();
         tags.put('p', value);
         assertThatThrownBy(() -> new DomainKey(tags)).isInstanceOf(DkimException.class);
      }
   }

   @Test
   void acceptsFoldingWhitespaceInRsaBase64() {
      Map<Character, String> tags = rsaTags();
      String key = tags.get('p');
      tags.put('p', " \t" + key.substring(0, 35) + "\r\n \t" + key.substring(35) + " ");

      assertThat(new DomainKey(tags).getPublicKey().getEncoded()).isEqualTo(rsaKeyPair.getPublic().getEncoded());
   }

   @Test
   void decodesRawEd25519DnsKeyFromRfc8463() {
      DomainKey domainKey = new DomainKey(ed25519Tags());

      assertThat(domainKey.getPublicKeyType()).isEqualTo(KeyPairType.ED25519);
      assertThat(((EdDSAPublicKey) domainKey.getPublicKey()).getPointEncoding())
            .isEqualTo(Base64.getDecoder().decode(ED25519_PUBLIC));
   }

   @Test
   void continuesAcceptingLegacyX509Ed25519DnsKeys() {
      DomainKey raw = new DomainKey(ed25519Tags());
      Map<Character, String> wrapped = ed25519Tags();
      wrapped.put('p', Base64.getEncoder().encodeToString(raw.getPublicKey().getEncoded()));

      assertThat(new DomainKey(wrapped).getPublicKey().getEncoded()).isEqualTo(raw.getPublicKey().getEncoded());
   }

   @Test
   void rejectsMismatchedEd448PublicKeyLabeledAsEd25519() throws Exception {
      KeyPair ed448 = KeyPairGenerator.getInstance("Ed448", new BouncyCastleProvider()).generateKeyPair();
      Map<Character, String> tags = ed25519Tags();
      tags.put('p', Base64.getEncoder().encodeToString(ed448.getPublic().getEncoded()));

      assertThatThrownBy(() -> new DomainKey(tags)).isInstanceOf(DkimException.class)
            .hasMessageContaining("couldn't be decoded").hasCauseInstanceOf(InvalidKeySpecException.class);
   }

   @Test
   void acceptsFoldingWhitespaceInEd25519Base64() {
      Map<Character, String> tags = ed25519Tags();
      tags.put('p', ED25519_PUBLIC.substring(0, 12) + "\r\n \t" + ED25519_PUBLIC.substring(12));

      assertThat(new DomainKey(tags).getPublicKey().getEncoded())
            .isEqualTo(new DomainKey(ed25519Tags()).getPublicKey().getEncoded());
   }

   @Test
   void checksMatchingEd25519KeysUsingBouncyCastleProvider() throws Exception {
      assertThatCode(() -> new DomainKey(ed25519Tags()).check("person@example.com", ed25519PrivateKey()))
            .doesNotThrowAnyException();
   }

   @Test
   void rejectsIncorrectEd25519KeyLengths() {
      for (int length : new int[] { 0, 31, 33, 64 }) {
         Map<Character, String> tags = ed25519Tags();
         tags.put('p', Base64.getEncoder().encodeToString(new byte[length]));
         assertThatThrownBy(() -> new DomainKey(tags)).isInstanceOf(DkimException.class);
      }
   }

   @Test
   void rejectsDifferentEd25519PrivateKeyWithAcceptanceException() throws Exception {
      DomainKey domainKey = new DomainKey(ed25519Tags());
      KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519", "BC");
      PrivateKey other = generator.generateKeyPair().getPrivate();

      assertThatThrownBy(() -> domainKey.check(null, other))
            .isInstanceOf(DkimAcceptanceException.class).hasMessage("Incompatible private and public key.");
   }

   @Test
   void rejectsWrongPrivateKeyTypeWithSigningException() {
      assertThatThrownBy(() -> new DomainKey(ed25519Tags()).check(null, rsaKeyPair.getPrivate()))
            .isInstanceOf(DkimSigningException.class).hasMessage("Performing cryptography failed.");
   }

   @Test
   void retainsExistingTagsViewAndMutableServiceTypesContract() {
      Map<Character, String> tags = rsaTags();
      DomainKey domainKey = new DomainKey(tags);
      tags.put('n', "added later");

      assertThat(domainKey.getTags()).containsEntry('n', "added later");
      assertThatThrownBy(() -> domainKey.getTags().put('n', "change")).isInstanceOf(UnsupportedOperationException.class);
      domainKey.getServiceTypes().add("custom");
      assertThat(domainKey.getServiceTypes()).contains("custom");
   }

   private Map<Character, String> rsaTags() {
      Map<Character, String> tags = new HashMap<Character, String>();
      tags.put('p', Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded()));
      return tags;
   }

   private Map<Character, String> ed25519Tags() {
      Map<Character, String> tags = new HashMap<Character, String>();
      tags.put('k', "ed25519");
      tags.put('p', ED25519_PUBLIC);
      return tags;
   }

   private PrivateKey ed25519PrivateKey() throws Exception {
      Ed25519PrivateKeyParameters parameters = new Ed25519PrivateKeyParameters(Base64.getDecoder().decode(ED25519_SECRET), 0);
      byte[] encoded = PrivateKeyInfoFactory.createPrivateKeyInfo(parameters).getEncoded();
      return KeyFactory.getInstance("Ed25519", "BC").generatePrivate(new PKCS8EncodedKeySpec(encoded));
   }
}
