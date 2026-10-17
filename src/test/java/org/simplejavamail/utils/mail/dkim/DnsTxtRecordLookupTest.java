package org.simplejavamail.utils.mail.dkim;

import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Iterator;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DnsTxtRecordLookupTest {

   @Test
   void closesEnumerationAndContextAfterSuccessfulLookup() {
      TestLookup lookup = lookupWith("\"v=DKIM1; p=abc\" \"def==\"");

      assertThat(lookup.lookup("test", environment())).isEqualTo("v=DKIM1; p=abcdef==");
      assertThat(lookup.records.closed).isTrue();
      assertThat(lookup.contextClosed).isTrue();
      assertThat(lookup.recordName).isEqualTo("test");
      assertThat(lookup.requestedAttributes).containsExactly("TXT");
   }

   @Test
   void passesProviderEnvironmentToContextCreation() {
      TestLookup lookup = lookupWith("p=abc");
      Hashtable<String, String> environment = environment();
      environment.put("java.naming.provider.url", "dns://127.0.0.1");

      lookup.lookup("test", environment);

      assertThat(lookup.environment).isEqualTo(environment);
   }

   @Test
   void closesContextWhenTxtAttributeIsMissing() {
      TestLookup lookup = lookupWith("unused");
      lookup.attributes = new BasicAttributes(true);

      assertThatThrownBy(() -> lookup.lookup("missing", environment()))
            .isInstanceOf(DkimException.class).hasMessage("There is no TXT record available for missing");
      assertThat(lookup.contextClosed).isTrue();
   }

   @Test
   void closesResourcesWhenTxtAttributeHasNoValues() {
      TestLookup lookup = lookupWith();

      assertThatThrownBy(() -> lookup.lookup("empty", environment()))
            .isInstanceOf(DkimException.class).hasMessage("Value of RR empty couldn't be retrieved");
      assertThat(lookup.records.closed).isTrue();
      assertThat(lookup.contextClosed).isTrue();
   }

   @Test
   void closesResourcesWhenRecordCannotBeParsed() {
      TestLookup lookup = lookupWith("\"\"");

      assertThatThrownBy(() -> lookup.lookup("empty", environment()))
            .isInstanceOf(DkimException.class).hasMessageContaining("Unable to parse DKIM record");
      assertThat(lookup.records.closed).isTrue();
      assertThat(lookup.contextClosed).isTrue();
   }

   @Test
   void preservesNamingFailureAndClosesContext() {
      TestLookup lookup = lookupWith("unused");
      NamingException failure = new NamingException("lookup failed");
      lookup.lookupFailure = failure;

      assertThatThrownBy(() -> lookup.lookup("test", environment()))
            .isInstanceOf(DkimException.class).hasMessage("Selector lookup failed").hasCause(failure);
      assertThat(lookup.contextClosed).isTrue();
   }

   @Test
   void closesResourcesAfterEnumerationFailureWithoutMaskingCause() {
      TestLookup lookup = lookupWith("p=abc");
      NamingException failure = new NamingException("iteration failed");
      lookup.records.iterationFailure = failure;
      lookup.records.closeFailure = new NamingException("enumeration cleanup failed");
      lookup.closeFailure = new NamingException("context cleanup failed");

      assertThatThrownBy(() -> lookup.lookup("test", environment()))
            .isInstanceOf(DkimException.class).hasCause(failure);
      assertThat(lookup.records.closed).isTrue();
      assertThat(lookup.contextClosed).isTrue();
   }

   @Test
   void cleanupFailuresDoNotReplaceSuccessfulResult() {
      TestLookup lookup = lookupWith("p=abc");
      lookup.records.closeFailure = new NamingException("enumeration cleanup failed");
      lookup.closeFailure = new NamingException("context cleanup failed");

      assertThat(lookup.lookup("test", environment())).isEqualTo("p=abc");
      assertThat(lookup.contextClosed).isTrue();
   }

   @Test
   void wrapsContextCreationFailure() {
      NamingException failure = new NamingException("cannot initialize DNS");
      DnsTxtRecordLookup lookup = new DnsTxtRecordLookup() {
         @Override
         DirContext createContext(Hashtable<String, String> environment) throws NamingException {
            throw failure;
         }
      };

      assertThatThrownBy(() -> lookup.lookup("test", environment()))
            .isInstanceOf(DkimException.class).hasMessage("Selector lookup failed").hasCause(failure);
   }

   private TestLookup lookupWith(String... values) {
      TestEnumeration records = new TestEnumeration(values);
      Attribute attribute = new BasicAttribute("TXT") {
         @Override
         public NamingEnumeration<?> getAll() {
            return records;
         }
      };
      BasicAttributes attributes = new BasicAttributes(true);
      attributes.put(attribute);
      return new TestLookup(attributes, records);
   }

   private Hashtable<String, String> environment() {
      Hashtable<String, String> environment = new Hashtable<String, String>();
      environment.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
      return environment;
   }

   private static final class TestLookup extends DnsTxtRecordLookup {
      private BasicAttributes attributes;
      private final TestEnumeration records;
      private boolean contextClosed;
      private NamingException lookupFailure;
      private NamingException closeFailure;
      private String recordName;
      private String[] requestedAttributes;
      private Hashtable<String, String> environment;

      private TestLookup(BasicAttributes attributes, TestEnumeration records) {
         this.attributes = attributes;
         this.records = records;
      }

      @Override
      DirContext createContext(Hashtable<String, String> environment) {
         this.environment = environment;
         return (DirContext) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] { DirContext.class },
               (proxy, method, arguments) -> {
                  if ("getAttributes".equals(method.getName())) {
                     recordName = (String) arguments[0];
                     requestedAttributes = (String[]) arguments[1];
                     if (lookupFailure != null) {
                        throw lookupFailure;
                     }
                     return attributes;
                  }
                  if ("close".equals(method.getName())) {
                     contextClosed = true;
                     if (closeFailure != null) {
                        throw closeFailure;
                     }
                     return null;
                  }
                  throw new UnsupportedOperationException(method.getName());
               });
      }
   }

   private static final class TestEnumeration implements NamingEnumeration<String> {
      private final Iterator<String> values;
      private boolean closed;
      private NamingException iterationFailure;
      private NamingException closeFailure;

      private TestEnumeration(String[] values) {
         this.values = Arrays.asList(values).iterator();
      }

      @Override
      public String next() {
         return values.next();
      }

      @Override
      public boolean hasMore() throws NamingException {
         if (iterationFailure != null) {
            throw iterationFailure;
         }
         return values.hasNext();
      }

      @Override
      public void close() throws NamingException {
         closed = true;
         if (closeFailure != null) {
            throw closeFailure;
         }
      }

      @Override
      public boolean hasMoreElements() {
         return values.hasNext();
      }

      @Override
      public String nextElement() {
         return values.next();
      }
   }
}
