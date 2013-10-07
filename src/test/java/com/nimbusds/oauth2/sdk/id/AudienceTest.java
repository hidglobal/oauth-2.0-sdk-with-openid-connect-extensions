package com.nimbusds.oauth2.sdk.id;


import java.util.List;

import junit.framework.TestCase;


/**
 * Tests the audience class.
 *
 * @author Vladimir Dzhuvinov
 */
public class AudienceTest extends TestCase {


	public void testToAudienceList() {

		Audience audience = new Audience("http://client.com");

		List<Audience> audienceList = audience.toSingleAudienceList();

		assertEquals("http://client.com", audienceList.get(0).getValue());
		assertEquals(1, audienceList.size());
	}

}
