package org.simplejavamail.utils.mail.dkim;

import java.util.Hashtable;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

/** Owns the JNDI resources for a single TXT lookup. */
class DnsTxtRecordLookup {

   String lookup(String recordName, Hashtable<String, String> environment) {
      DirContext context = null;
      NamingEnumeration<?> records = null;
      try {
         context = createContext(environment);
         Attributes attributes = context.getAttributes(recordName, new String[] { "TXT" });
         Attribute txtRecord = attributes.get("txt");
         if (txtRecord == null) {
            throw new DkimException("There is no TXT record available for " + recordName);
         }

         StringBuilder builder = new StringBuilder();
         records = txtRecord.getAll();
         while (records.hasMore()) {
            builder.append((String) records.next());
         }
         if (builder.length() == 0) {
            throw new DkimException("Value of RR " + recordName + " couldn't be retrieved");
         }
         return DomainKeyRecord.unquote(builder.toString());
      } catch (NamingException e) {
         throw new DkimException("Selector lookup failed", e);
      } finally {
         if (records != null) {
            try {
               records.close();
            } catch (NamingException ignored) {
               // Cleanup must not replace a lookup result or its original failure.
            }
         }
         if (context != null) {
            try {
               context.close();
            } catch (NamingException ignored) {
               // Still close the context when enumeration cleanup fails.
            }
         }
      }
   }

   DirContext createContext(Hashtable<String, String> environment) throws NamingException {
      return new InitialDirContext(environment);
   }
}
