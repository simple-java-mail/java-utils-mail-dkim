package org.simplejavamail.utils.mail.dkim;

import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DomainKeyRecordTest {

   @Test
   void parsesWhitespaceAroundNamesEqualsAndValues() {
      Map<Character, String> tags = DomainKeyRecord.parseTags(" \tv \t= DKIM1 ; k = rsa ; p = abc== ; ", "test");

      assertThat(tags).containsEntry('v', "DKIM1").containsEntry('k', "rsa").containsEntry('p', "abc==");
   }

   @Test
   void preservesWhitespaceInsideValues() {
      assertThat(DomainKeyRecord.parseTags("n=two words; p=ab\r\n cd==", "test"))
            .containsEntry('n', "two words").containsEntry('p', "ab\r\n cd==");
   }

   @Test
   void ignoresMultiCharacterExtensionsWithoutOverwritingKnownTags() {
      assertThat(DomainKeyRecord.parseTags("p=key; preference=ignored; v=DKIM1; version2=ignored", "test"))
            .containsOnlyKeys('p', 'v').containsEntry('p', "key").containsEntry('v', "DKIM1");
   }

   @Test
   void preservesExistingLastDuplicateWinsBehavior() {
      assertThat(DomainKeyRecord.parseTags("p=old;p=new", "test")).containsEntry('p', "new");
   }

   @Test
   void preservesEmptyValuesAndCaseSensitiveNames() {
      assertThat(DomainKeyRecord.parseTags("p=; P=upper; k=rsa", "test"))
            .containsEntry('p', "").containsEntry('P', "upper").containsEntry('k', "rsa");
   }

   @Test
   void rejectsMissingEqualsWithRecordContext() {
      assertThatThrownBy(() -> DomainKeyRecord.parseTags("p", "selector._domainkey.example.com"))
            .isInstanceOf(DkimException.class).hasMessageContaining("selector._domainkey.example.com");
   }

   @Test
   void retainsPreviouslyAcceptedMalformedSeparators() {
      assertThat(DomainKeyRecord.parseTags("pXkey;=value", "test"))
            .containsEntry('p', "key").containsEntry('=', "alue");
   }

   @Test
   void acceptsFoldedQuotedJndiChunks() {
      assertThat(DomainKeyRecord.unquote("\"v=DKIM1; p=ab\r\n cd\" \"ef==\""))
            .isEqualTo("v=DKIM1; p=ab\r\n cdef==");
   }

   @Test
   void unquotesSingleAndMultipleJndiChunks() {
      assertThat(DomainKeyRecord.unquote("\"v=DKIM1; p=abc\" \"def==\""))
            .isEqualTo("v=DKIM1; p=abcdef==");
      assertThat(DomainKeyRecord.unquote("\"v=DKIM1; p=abc\" def=="))
            .isEqualTo("v=DKIM1; p=abcdef==");
      assertThat(DomainKeyRecord.unquote("'v=DKIM1; p=abc' 'def=='"))
            .isEqualTo("v=DKIM1; p=abcdef==");
   }

   @Test
   void acceptsUnquotedJndiValues() {
      assertThat(DomainKeyRecord.unquote("v=DKIM1;p=abc==")).isEqualTo("v=DKIM1;p=abc==");
   }

   @Test
   void rejectsEmptyTxtValues() {
      assertThatThrownBy(() -> DomainKeyRecord.unquote("\"\""))
            .isInstanceOf(DkimException.class).hasMessageContaining("Unable to parse DKIM record");
   }
}
