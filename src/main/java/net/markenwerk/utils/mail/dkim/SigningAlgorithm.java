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
