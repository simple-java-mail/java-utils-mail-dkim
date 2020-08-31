package net.markenwerk.utils.mail.dkim;

import java.security.Security;
import java.util.Arrays;
import java.util.List;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public enum KeyPairType {

   RSA("rsa", "RSA", SigningAlgorithm.SHA256_WITH_RSA,
         new SigningAlgorithm[] { SigningAlgorithm.SHA256_WITH_RSA, SigningAlgorithm.SHA1_WITH_RSA }) {

      @Override
      protected void initialize() {
      }

   },

   ED25519("ed25519", "EdDSA", SigningAlgorithm.SHA256_WITH_ED25519,
         new SigningAlgorithm[] { SigningAlgorithm.SHA256_WITH_ED25519 }) {

      private boolean initailized;

      @Override
      protected void initialize() {
         if (!initailized) {
            Security.addProvider(new EdDSASecurityProvider());
            initailized = true;
         }
      }
      
   };

   private final String dkimNotation;

   private final String javaNotation;

   private final SigningAlgorithm defaultSigningAlgorithm;

   private final List<SigningAlgorithm> supportedSigningAlgorithms;

   private KeyPairType(String dkimNotation, String javaNotation, SigningAlgorithm defaultSigningAlgorithm,
         SigningAlgorithm[] supportedSigningAlgorithms) {
      this.dkimNotation = dkimNotation;
      this.javaNotation = javaNotation;
      this.defaultSigningAlgorithm = defaultSigningAlgorithm;
      this.supportedSigningAlgorithms = Arrays.asList(supportedSigningAlgorithms);
   }

   public String getDkimNotation() {
      return dkimNotation;
   }

   public String getJavaNotation() {
      return javaNotation;
   }

   public SigningAlgorithm getDefaultSigningAlgorithm() {
      return defaultSigningAlgorithm;
   }

   public boolean supportsSigningAlgorithm(SigningAlgorithm signingAlgorithm) {
      return supportedSigningAlgorithms.contains(signingAlgorithm);
   }

   protected abstract void initialize();

}
