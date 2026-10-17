package org.simplejavamail.utils.mail.dkim;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DomainKeyCacheTest {

   private static final String RECORD = "v=DKIM1;p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB";

   private long originalTtl;
   private String originalProvider;

   @BeforeEach
   void configureCache() {
      originalTtl = DomainKeyUtil.getCacheTtl();
      originalProvider = DomainKeyUtil.getDnsProviderUrl();
      DomainKeyUtil.setDnsProviderUrl(null);
      DomainKeyUtil.setCacheTtl(60_000);
   }

   @AfterEach
   void restoreCache() {
      DomainKeyUtil.setCacheTtl(originalTtl);
      DomainKeyUtil.setDnsProviderUrl(originalProvider);
   }

   @Test
   void cachesSuccessfulLookups() {
      CountingLookup lookup = new CountingLookup();
      DomainKey first = DomainKeyUtil.getDomainKey("test", lookup);

      assertThat(DomainKeyUtil.getDomainKey("test", lookup)).isSameAs(first);
      assertThat(lookup.calls.get()).isEqualTo(1);
   }

   @Test
   void separatesSelectorsAndDomains() {
      CountingLookup lookup = new CountingLookup();
      DomainKey first = DomainKeyUtil.getDomainKey("one._domainkey.example.com", lookup);

      assertThat(DomainKeyUtil.getDomainKey("two._domainkey.example.com", lookup)).isNotSameAs(first);
      assertThat(DomainKeyUtil.getDomainKey("one._domainkey.other.com", lookup)).isNotSameAs(first);
      assertThat(lookup.calls.get()).isEqualTo(3);
   }

   @Test
   void zeroTtlDisablesReuseAndDoesNotResurrectOldKeys() {
      CountingLookup lookup = new CountingLookup();
      DomainKey first = DomainKeyUtil.getDomainKey("test", lookup);
      DomainKeyUtil.setCacheTtl(0);
      DomainKey second = DomainKeyUtil.getDomainKey("test", lookup);

      assertThat(second).isNotSameAs(first);
      assertThat(DomainKeyUtil.getDomainKey("test", lookup)).isNotSameAs(second);
      DomainKeyUtil.setCacheTtl(60_000);
      assertThat(DomainKeyUtil.getDomainKey("test", lookup)).isNotSameAs(first).isNotSameAs(second);
      assertThat(lookup.calls.get()).isEqualTo(4);
   }

   @Test
   void negativeTtlRestoresDefault() {
      DomainKeyUtil.setCacheTtl(-1);

      assertThat(DomainKeyUtil.getCacheTtl()).isEqualTo(2 * 60 * 60 * 1000);
   }

   @Test
   void longTtlDoesNotOverflowTimestampArithmetic() {
      DomainKeyUtil.setCacheTtl(Long.MAX_VALUE);
      CountingLookup lookup = new CountingLookup();
      DomainKey first = DomainKeyUtil.getDomainKey("test", lookup);

      assertThat(DomainKeyUtil.getDomainKey("test", lookup)).isSameAs(first);
      assertThat(lookup.calls.get()).isEqualTo(1);
   }

   @Test
   void reloadsExpiredKeysUsingDeterministicClock() {
      DomainKeyUtil.setCacheTtl(1000);
      CountingLookup lookup = new CountingLookup();
      DomainKey first = DomainKeyUtil.getDomainKey("test", lookup);

      assertThat(DomainKeyUtil.getDomainKey("test", lookup, () -> first.getTimestamp() + 999)).isSameAs(first);
      assertThat(DomainKeyUtil.getDomainKey("test", lookup, () -> first.getTimestamp() + 1000)).isNotSameAs(first);
      assertThat(lookup.calls.get()).isEqualTo(2);
   }

   @Test
   void periodicallyEvictsExpiredKeysThatAreNeverRequestedAgain() {
      DomainKeyUtil.setCacheTtl(1000);
      CountingLookup lookup = new CountingLookup();
      DomainKey old = DomainKeyUtil.getDomainKey("old", lookup);

      DomainKeyUtil.getDomainKey("different", lookup, () -> old.getTimestamp() + 2000);
      DomainKeyUtil.setCacheTtl(Long.MAX_VALUE);

      assertThat(DomainKeyUtil.getDomainKey("old", lookup)).isNotSameAs(old);
      assertThat(lookup.calls.get()).isEqualTo(3);
   }

   @Test
   void cacheHitsStillEvictExpiredKeysThatAreNeverRequestedAgain() {
      DomainKeyUtil.setCacheTtl(1000);
      AtomicLong clock = new AtomicLong(10_000L);
      CountingLookup lookup = new CountingLookup();
      DomainKey old = DomainKeyUtil.getDomainKey("old", lookup, clock::get);
      clock.set(10_500L);
      DomainKey active = DomainKeyUtil.getDomainKey("active", lookup, clock::get);

      clock.set(11_000L);
      assertThat(DomainKeyUtil.getDomainKey("active", lookup, clock::get)).isSameAs(active);
      assertThat(lookup.calls.get()).isEqualTo(2);

      // Extending TTL must not bring an already evicted entry back into use.
      DomainKeyUtil.setCacheTtl(Long.MAX_VALUE);
      assertThat(DomainKeyUtil.getDomainKey("old", lookup, clock::get)).isNotSameAs(old);
      assertThat(lookup.calls.get()).isEqualTo(3);
   }

   @Test
   void providerChangesInvalidateCachedKeysAndNormalizeWhitespace() {
      CountingLookup lookup = new CountingLookup();
      DomainKey first = DomainKeyUtil.getDomainKey("test", lookup);
      DomainKeyUtil.setDnsProviderUrl("  dns://127.0.0.1  ");

      assertThat(DomainKeyUtil.getDomainKey("test", lookup)).isNotSameAs(first);
      assertThat(DomainKeyUtil.getDnsProviderUrl()).isEqualTo("dns://127.0.0.1");
      assertThat(lookup.environment).containsEntry("java.naming.provider.url", "dns://127.0.0.1");
      DomainKeyUtil.setDnsProviderUrl(" \t");
      DomainKeyUtil.getDomainKey("test", lookup);
      assertThat(lookup.environment).doesNotContainKey("java.naming.provider.url");
   }

   @Test
   void failuresAreNotCached() {
      AtomicInteger calls = new AtomicInteger();
      DnsTxtRecordLookup lookup = new DnsTxtRecordLookup() {
         @Override
         String lookup(String name, Hashtable<String, String> environment) {
            if (calls.incrementAndGet() == 1) {
               throw new DkimException("temporary failure");
            }
            return RECORD;
         }
      };

      assertThatThrownBy(() -> DomainKeyUtil.getDomainKey("test", lookup))
            .isInstanceOf(DkimException.class).hasMessage("temporary failure");
      assertThat(DomainKeyUtil.getDomainKey("test", lookup)).isNotNull();
      assertThat(calls.get()).isEqualTo(2);
   }

   @Test
   void concurrentCallersReuseOneLookupForSameRecord() throws Exception {
      ExecutorService executor = Executors.newFixedThreadPool(8);
      BlockingLookup lookup = new BlockingLookup();
      try {
         List<Future<DomainKey>> results = new ArrayList<Future<DomainKey>>();
         for (int i = 0; i < 16; i++) {
            results.add(executor.submit(() -> DomainKeyUtil.getDomainKey("test", lookup)));
         }
         assertThat(lookup.started.await(5, TimeUnit.SECONDS)).isTrue();
         lookup.release.countDown();
         DomainKey first = results.get(0).get(5, TimeUnit.SECONDS);
         for (Future<DomainKey> result : results) {
            assertThat(result.get(5, TimeUnit.SECONDS)).isSameAs(first);
         }
         assertThat(lookup.calls.get()).isEqualTo(1);
      } finally {
         lookup.release.countDown();
         executor.shutdownNow();
      }
   }

   @Test
   void slowDnsDoesNotBlockOtherRecordsOrConfiguration() throws Exception {
      ExecutorService executor = Executors.newFixedThreadPool(2);
      BlockingLookup slow = new BlockingLookup();
      try {
         Future<DomainKey> pending = executor.submit(() -> DomainKeyUtil.getDomainKey("slow", slow));
         assertThat(slow.started.await(5, TimeUnit.SECONDS)).isTrue();
         Future<DomainKey> independent = executor.submit(() -> {
            assertThat(DomainKeyUtil.getCacheTtl()).isEqualTo(60_000);
            return DomainKeyUtil.getDomainKey("fast", new CountingLookup());
         });

         assertThat(independent.get(5, TimeUnit.SECONDS)).isNotNull();
         assertThat(pending.isDone()).isFalse();
      } finally {
         slow.release.countDown();
         executor.shutdownNow();
      }
   }

   @Test
   void providerChangesDuringLookupCannotRepopulateOldProviderCache() throws Exception {
      ExecutorService executor = Executors.newSingleThreadExecutor();
      BlockingLookup old = new BlockingLookup();
      try {
         DomainKeyUtil.setDnsProviderUrl("dns://old");
         Future<DomainKey> pending = executor.submit(() -> DomainKeyUtil.getDomainKey("test", old));
         assertThat(old.started.await(5, TimeUnit.SECONDS)).isTrue();
         DomainKeyUtil.setDnsProviderUrl("dns://new");
         old.release.countDown();
         DomainKey oldResult = pending.get(5, TimeUnit.SECONDS);
         CountingLookup fresh = new CountingLookup();

         assertThat(DomainKeyUtil.getDomainKey("test", fresh)).isNotSameAs(oldResult);
         assertThat(fresh.environment).containsEntry("java.naming.provider.url", "dns://new");
         assertThat(fresh.calls.get()).isEqualTo(1);
      } finally {
         old.release.countDown();
         executor.shutdownNow();
      }
   }

   @Test
   void disablingCacheDuringLookupPreventsOldResultsFromBeingRetained() throws Exception {
      ExecutorService executor = Executors.newSingleThreadExecutor();
      BlockingLookup old = new BlockingLookup();
      try {
         Future<DomainKey> pending = executor.submit(() -> DomainKeyUtil.getDomainKey("test", old));
         assertThat(old.started.await(5, TimeUnit.SECONDS)).isTrue();
         DomainKeyUtil.setCacheTtl(0);
         DomainKeyUtil.setCacheTtl(60_000);
         old.release.countDown();
         DomainKey oldResult = pending.get(5, TimeUnit.SECONDS);
         CountingLookup fresh = new CountingLookup();

         assertThat(DomainKeyUtil.getDomainKey("test", fresh)).isNotSameAs(oldResult);
         assertThat(fresh.calls.get()).isEqualTo(1);
      } finally {
         old.release.countDown();
         executor.shutdownNow();
      }
   }

   private static class CountingLookup extends DnsTxtRecordLookup {
      final AtomicInteger calls = new AtomicInteger();
      Hashtable<String, String> environment;

      @Override
      String lookup(String name, Hashtable<String, String> environment) {
         calls.incrementAndGet();
         this.environment = environment;
         return RECORD;
      }
   }

   private static final class BlockingLookup extends CountingLookup {
      private final CountDownLatch started = new CountDownLatch(1);
      private final CountDownLatch release = new CountDownLatch(1);

      @Override
      String lookup(String name, Hashtable<String, String> environment) {
         started.countDown();
         try {
            if (!release.await(5, TimeUnit.SECONDS)) {
               throw new DkimException("Test DNS lookup was not released");
            }
         } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new DkimException("Test DNS lookup was interrupted", e);
         }
         return super.lookup(name, environment);
      }
   }
}
