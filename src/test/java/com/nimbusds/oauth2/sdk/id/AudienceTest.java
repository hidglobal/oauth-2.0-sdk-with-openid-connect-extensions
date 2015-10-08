package com.nimbusds.oauth2.sdk.id;


import java.net.URI;
import java.util.List;

import junit.framework.TestCase;


/**
 * Tests the audience class.
 */
public class AudienceTest extends TestCase {


	public void testToAudienceList() {

		Audience audience = new Audience("http://client.com");

		List<Audience> audienceList = audience.toSingleAudienceList();

		assertEquals("http://client.com", audienceList.get(0).getValue());
		assertEquals(1, audienceList.size());
	}


	public void testURIConstructor() {

		URI uri = URI.create("https://c2id.com");
		Audience aud = new Audience(uri);
		assertEquals(uri.toString(), aud.getValue());
		assertTrue(aud.equals(new Audience("https://c2id.com")));
	}


	public void testClientIDConstructor() {

		ClientID clientID = new ClientID("123");
		Audience aud = new Audience(clientID);
		assertEquals(clientID.toString(), aud.getValue());
		assertTrue(aud.equals(new Audience("123")));
	}
}
