package org.simplejavamail.utils.mail.dkim;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.function.LongSupplier;

/**
 * @author Torsten Krause (tk at markenwerk dot net)
 * @author Florian Sager
 * @since 1.0.0
 */
public final class DomainKeyUtil {

   private static final Map<String, DomainKey> CACHE = new HashMap<String, DomainKey>();

   private static final DnsTxtRecordLookup DNS_LOOKUP = new DnsTxtRecordLookup();

   // Serialize lookups for a record without holding the global configuration lock
   // during DNS access. A fixed array avoids retaining a lock for every selector.
   private static final Object[] LOOKUP_LOCKS = new Object[32];

   static {
      for (int i = 0; i < LOOKUP_LOCKS.length; i++) {
         LOOKUP_LOCKS[i] = new Object();
      }
   }

   private static final long DEFAULT_CACHE_TTL = 2 * 60 * 60 * 1000;

   private static long cacheTtl = DEFAULT_CACHE_TTL;
   private static String dnsProviderUrl;
   private static long cacheGeneration;
   private static long lastCleanupTimestamp;

   private DomainKeyUtil() {
   }

   /**
    * Returns the configured TTL (time to live) for retrieved {@link DomainKey} s.
    * 
    * @return The configured TTL for retrieved {@link DomainKey}s.
    */
   public static synchronized long getCacheTtl() {
      return cacheTtl;
   }

   /**
    * Sets the TTL (time to live) for retrieved {@link DomainKey}s.
    * 
    * @param cacheTtl The TTL for retrieved {@link DomainKey}s.
    */
   public static synchronized void setCacheTtl(long cacheTtl) {
      if (cacheTtl < 0) {
         cacheTtl = DEFAULT_CACHE_TTL;
      }
      DomainKeyUtil.cacheTtl = cacheTtl;
      lastCleanupTimestamp = 0;
      if (cacheTtl == 0) {
         cacheGeneration++;
         CACHE.clear();
      }
   }

   /**
    * Returns the JNDI DNS provider URL used for DKIM record lookups.
    *
    * @return The configured DNS provider URL, or {@code null} to use the JVM default.
    */
   public static synchronized String getDnsProviderUrl() {
      return dnsProviderUrl;
   }

   /**
    * Sets the JNDI DNS provider URL used for DKIM record lookups.
    *
    * @param dnsProviderUrl The DNS provider URL, for example {@code dns://8.8.8.8},
    *                       or {@code null} to use the JVM default.
    */
   public static synchronized void setDnsProviderUrl(String dnsProviderUrl) {
      String normalizedDnsProviderUrl = null;
      if (null != dnsProviderUrl) {
         normalizedDnsProviderUrl = dnsProviderUrl.trim();
         if (normalizedDnsProviderUrl.length() == 0) {
            normalizedDnsProviderUrl = null;
         }
      }

      DomainKeyUtil.dnsProviderUrl = normalizedDnsProviderUrl;
      cacheGeneration++;
      lastCleanupTimestamp = 0;
      CACHE.clear();
   }

   /**
    * Retrieves the {@link DomainKey} for the given signing domain and selector.
    * 
    * @param signingDomain The signing domain.
    * @param selector      The selector.
    * @return The retrieved {@link DomainKey}.
    * @throws DkimException If the domain key couldn't be retrieved or if either
    *                       the version, key type or service type given in the tags
    *                       of the retrieved domain key is incompatible to this
    *                       library ('DKIM1', 'RSA' and 'email' respectively).
    */
   public static DomainKey getDomainKey(String signingDomain, String selector) throws DkimException {
      return getDomainKey(getRecordName(signingDomain, selector), DNS_LOOKUP);
   }

   static DomainKey getDomainKey(String recordName, DnsTxtRecordLookup lookup) throws DkimException {
      return getDomainKey(recordName, lookup, System::currentTimeMillis);
   }

   static DomainKey getDomainKey(String recordName, DnsTxtRecordLookup lookup, LongSupplier clock) throws DkimException {
      Object lookupLock = LOOKUP_LOCKS[(recordName.hashCode() & Integer.MAX_VALUE) % LOOKUP_LOCKS.length];
      synchronized (lookupLock) {
         long generation;
         Hashtable<String, String> environment;
         synchronized (DomainKeyUtil.class) {
            long now = clock.getAsLong();
            // Sweep on cache hits as well, so a busy selector cannot retain
            // expired entries for selectors that are never requested again.
            if (now - lastCleanupTimestamp >= Math.min(cacheTtl, 60_000L)) {
               removeExpiredKeys(now);
               lastCleanupTimestamp = now;
            }
            DomainKey cached = CACHE.get(recordName);
            if (cached != null && cacheTtl != 0 && isRecent(cached, now)) {
               return cached;
            }
            CACHE.remove(recordName);
            generation = cacheGeneration;
            environment = getEnvironment();
         }

         DomainKey domainKey = new DomainKey(DomainKeyRecord.parseTags(lookup.lookup(recordName, environment), recordName),
               clock.getAsLong());
         synchronized (DomainKeyUtil.class) {
            if (generation == cacheGeneration && cacheTtl != 0) {
               CACHE.put(recordName, domainKey);
            }
         }
         return domainKey;
      }
   }

   private static boolean isRecent(DomainKey domainKey, long now) {
      return now - domainKey.getTimestamp() < cacheTtl;
   }

   private static void removeExpiredKeys(long now) {
      Iterator<DomainKey> keys = CACHE.values().iterator();
      while (keys.hasNext()) {
         DomainKey key = keys.next();
         if (cacheTtl == 0 || !isRecent(key, now)) {
            keys.remove();
         }
      }
   }

   /**
    * Retrieves the tags of a domain key for the given signing domain and selector.
    * 
    * @param signingDomain The signing domain.
    * @param selector      The selector.
    * @return The retrieved tags.
    * @throws DkimException If the domain key couldn't be retrieved.
    */
   public static Map<Character, String> getTags(String signingDomain, String selector) throws DkimException {
      String recordName = getRecordName(signingDomain, selector);
      return DomainKeyRecord.parseTags(DNS_LOOKUP.lookup(recordName, getEnvironment()), recordName);
   }

   /**
    * Retrieves the raw domain key for the given signing domain and selector.
    * 
    * @param signingDomain The signing domain.
    * @param selector      The selector.
    * @return The raw domain key.
    * @throws DkimException If the domain key couldn't be retrieved.
    */
   public static String getValue(String signingDomain, String selector) throws DkimException {
      return DNS_LOOKUP.lookup(getRecordName(signingDomain, selector), getEnvironment());
   }

   private static String getRecordName(String signingDomain, String selector) {
      return selector + "._domainkey." + signingDomain;
   }

   private static synchronized Hashtable<String, String> getEnvironment() {
      Hashtable<String, String> environment = new Hashtable<String, String>();
      environment.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
      if (null != dnsProviderUrl) {
         environment.put("java.naming.provider.url", dnsProviderUrl);
      }
      return environment;
   }

}
