package org.simplejavamail.utils.mail.dkim;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

/** Cryptographic state belongs to one message, never to a reusable signer. */
final class SigningOperation {

   private final SigningAlgorithm algorithm;
   private final MessageDigest digest;
   private final Signature signature;

   SigningOperation(KeyPairType keyType, SigningAlgorithm algorithm, PrivateKey key) {
      this(keyType, algorithm, key, true);
   }

   SigningOperation(KeyPairType keyType, SigningAlgorithm algorithm, PrivateKey key, boolean legacy) {
      this.algorithm = algorithm;
      try {
         digest = MessageDigest.getInstance(algorithm.getHashNotation());
      } catch (NoSuchAlgorithmException e) {
         throw new DkimException("Unknown hashing algorithm: " + algorithm.getHashNotation(), e);
      }
      try {
         if (keyType == KeyPairType.ED25519) {
            if (legacy) {
               keyType.initialize();
               signature = Signature.getInstance(algorithm.getJavaNotation(), "BC");
            } else {
               signature = Signature.getInstance(algorithm.getJavaNotation(), DkimCryptoProvider.INSTANCE);
            }
         } else {
            signature = Signature.getInstance(algorithm.getJavaNotation());
         }
         signature.initSign(key);
      } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
         throw new DkimException("Unknown signing algorithm " + algorithm.getJavaNotation(), e);
      } catch (InvalidKeyException e) {
         throw new DkimException("Invalid private key", e);
      }
   }

   byte[] digest(byte[] body) {
      return digest.digest(body);
   }

   byte[] sign(byte[] headers) throws DkimSigningException {
      try {
         // PureEd25519 signs the SHA-256 header hash, not the headers themselves.
         signature.update(algorithm == SigningAlgorithm.SHA256_WITH_ED25519 ? digest.digest(headers) : headers);
         return signature.sign();
      } catch (SignatureException e) {
         throw new DkimSigningException("Failed to create signature", e);
      }
   }
}
