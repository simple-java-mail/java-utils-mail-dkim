package org.simplejavamail.utils.mail.dkim;

/**
 * Allowed signing algorithms by RFC 4871 with translation to different Java
 * notations.
 * 
 * @author Torsten Krause (tk at markenwerk dot net)
 * @author Florian Sager
 * @since 1.0.0
 */
public enum SigningAlgorithm {

   /**
    * The rsa-sha256 signing algorithm.
    */
   SHA256_WITH_RSA("rsa-sha256", "SHA256withRSA", "sha-256"),

   /**
    * The rsa-sha1 signing algorithm.
    */
   SHA1_WITH_RSA("rsa-sha1", "SHA1withRSA", "sha-1"),

   /**
    * The rsa-sha1 signing algorithm.
    */
   SHA256_WITH_ED25519("ed25519-sha256", "NONEwithEdDSA", "sha-256");

   private final String dkimNotation;

   private final String javaNotation;

   private final String hashNotation;

   private SigningAlgorithm(String dkimNotation, String javaNotation, String hashNotation) {
      this.dkimNotation = dkimNotation;
      this.javaNotation = javaNotation;
      this.hashNotation = hashNotation;
   }

   public String getDkimNotation() {
      return dkimNotation;
   }

   public String getJavaNotation() {
      return javaNotation;
   }

   public String getHashNotation() {
      return hashNotation;
   }

}
