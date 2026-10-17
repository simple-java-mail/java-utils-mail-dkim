package org.simplejavamail.utils.mail.dkim;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Converts DNS TXT presentation values into the library's existing tag model. */
final class DomainKeyRecord {

   private static final Pattern RECORD_PATTERN = Pattern
         .compile("(?:\"(.*?)\"(?: |$))|(?:'(.*?)'(?: |$))|(?:(.*?)(?: |$))", Pattern.DOTALL);

   private DomainKeyRecord() {
   }

   static Map<Character, String> parseTags(String recordValue, String recordName) {
      Map<Character, String> tags = new HashMap<Character, String>();
      String[] parts = recordValue.split(";");
      for (int i = 0; i < parts.length; i++) {
         String tag = parts[i].trim();
         if (tag.length() == 0 && i == parts.length - 1 && i != 0) {
            continue;
         }
         int separator = tag.indexOf('=');
         if (separator < 1) {
            // Earlier releases accepted any second character as a separator.
            // Retain that permissiveness; stricter validation needs a separate
            // compatibility decision rather than silently tightening a patch.
            try {
               tags.put(tag.charAt(0), tag.substring(2));
            } catch (IndexOutOfBoundsException e) {
               throw new DkimException("The tag " + tag + " in RR " + recordName + " couldn't be decoded.", e);
            }
            continue;
         }
         String name = tag.substring(0, separator).trim();
         // The public map uses Character keys. Extension names cannot be
         // represented and must not overwrite a known tag sharing their prefix.
         if (name.length() == 1) {
            tags.put(name.charAt(0), tag.substring(separator + 1).trim());
         }
      }
      return tags;
   }

   /* JNDI can mix quoted and unquoted chunks of one TXT record. */
   static String unquote(String recordValue) {
      Matcher recordMatcher = RECORD_PATTERN.matcher(recordValue);
      StringBuilder builder = new StringBuilder();
      while (recordMatcher.find()) {
         for (int i = 1; i <= recordMatcher.groupCount(); i++) {
            String match = recordMatcher.group(i);
            if (match != null) {
               builder.append(match);
            }
         }
      }
      if (builder.length() == 0) {
         throw new DkimException("Unable to parse DKIM record: " + recordValue);
      }
      return builder.toString();
   }
}
