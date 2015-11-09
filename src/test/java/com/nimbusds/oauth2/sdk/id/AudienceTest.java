package com.nimbusds.oauth2.sdk.id;


import java.net.URI;
import java.util.Arrays;
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


	public void testToStringListSingle() {

		assertNull(Audience.toStringList((Audience)null));

		assertEquals("A", Audience.toStringList(new Audience("A")).get(0));
		assertEquals(1, Audience.toStringList(new Audience("A")).size());
	}


	public void testToStringList() {

		assertNull(Audience.toStringList((List<Audience>)null));

		assertEquals("A", Audience.toStringList(Arrays.asList(new Audience("A"), new Audience("B"))).get(0));
		assertEquals("B", Audience.toStringList(Arrays.asList(new Audience("A"), new Audience("B"))).get(1));
		assertEquals(2, Audience.toStringList(Arrays.asList(new Audience("A"), new Audience("B"))).size());
	}


	public void testFromStringList() {

		assertNull(Audience.create((List<String>)null));

		assertEquals(new Audience("A"), Audience.create(Arrays.asList("A", "B")).get(0));
		assertEquals(new Audience("B"), Audience.create(Arrays.asList("A", "B")).get(1));
		assertEquals(2, Audience.create(Arrays.asList("A", "B")).size());
	}


	public void testMatchesAny() {

		assertTrue(Audience.matchesAny(Audience.create("A"), Audience.create("A")));
		assertTrue(Audience.matchesAny(Audience.create("A", "B"), Audience.create("A")));
		assertTrue(Audience.matchesAny(Audience.create("A"), Audience.create("A", "B")));
		assertFalse(Audience.matchesAny(Audience.create("A"), Audience.create("B")));
		assertFalse(Audience.matchesAny(Audience.create("B"), Audience.create("A")));
		assertFalse(Audience.matchesAny(Audience.create("B", "B"), Audience.create("A", "A")));
		assertFalse(Audience.matchesAny(null, Audience.create("A", "A")));
		assertFalse(Audience.matchesAny(Audience.create("A", "A"), null));
		assertFalse(Audience.matchesAny(null, null));
	}
}
