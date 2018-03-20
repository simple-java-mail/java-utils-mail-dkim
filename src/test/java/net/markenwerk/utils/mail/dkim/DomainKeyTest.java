package net.markenwerk.utils.mail.dkim;

import static org.junit.Assert.assertNotNull;

import java.util.HashMap;
import java.util.Map;

import org.junit.Ignore;
import org.junit.Test;

public class DomainKeyTest {
	
	/** 
	 * Test a valid record using the example public key from the DKIM spec page
	 * http://dkim.org/specs/rfc4871-dkimbase.html
	 */
	@Ignore
	@Test
	public void happyCase() {
		Map<Character, String> tags = new HashMap<Character, String>();
		tags.put('v', "DKIM1");
		tags.put('p', "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB");
		
		DomainKey dk = new DomainKey(tags);
		assertNotNull(dk);
	}
	
	/**
	 * Some DNS servers give multiple records concatenated by "\" \"", this happens frequently with larger keys. Note that the original quote will be
	 * at the start of the the TXT record and so we will not see it at the start of the p= tag.
	 */
	@Test
	public void multipleStringCase() {
		Map<Character, String> tags = new HashMap<Character, String>();
		tags.put('v', "DKIM1");
		tags.put('p', "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMm\" \"PSPDdQPNUYckcQ2QIDAQAB");
		
		//DomainKey dk = new DomainKey(tags);
		//assertNotNull(dk);		
		DomainKeyUtil.getDomainKey("scb.co.th", "14531180319");
	}
}
