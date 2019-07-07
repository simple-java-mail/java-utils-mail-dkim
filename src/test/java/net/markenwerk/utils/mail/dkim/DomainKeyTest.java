package net.markenwerk.utils.mail.dkim;

import static org.junit.Assert.assertNotNull;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

public class DomainKeyTest {

	/**
	 * Test a valid record using the example public key from the DKIM spec page
	 * http://dkim.org/specs/rfc4871-dkimbase.html
	 */
	@Test
	public void happyCase() {
		Map<Character, String> tags = new HashMap<Character, String>();
		tags.put('v', "DKIM1");
		tags.put('p',
				"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB");

		DomainKey dk = new DomainKey(tags);
		assertNotNull(dk);
	}
}
