package org.simplejavamail.utils.mail.dkim;

import java.security.Provider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** A private provider instance; never installed in the JVM provider registry. */
final class DkimCryptoProvider {
   static final Provider INSTANCE = new BouncyCastleProvider();
   private DkimCryptoProvider() { }
}
