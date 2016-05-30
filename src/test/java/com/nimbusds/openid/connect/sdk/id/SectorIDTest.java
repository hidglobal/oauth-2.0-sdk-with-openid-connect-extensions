package com.nimbusds.openid.connect.sdk.id;


import java.net.URI;

import junit.framework.TestCase;


public class SectorIDTest extends TestCase {
	

	public void testStringConstructor() {

		SectorID sectorID = new SectorID("example.com");
		assertEquals("example.com", sectorID.getValue());
	}


	public void testURIConstructor() {

		SectorID sectorID = new SectorID(URI.create("https://example.com"));
		assertEquals("example.com", sectorID.getValue());
	}


	public void testURIConstructor_missingHost() {

		try {
			new SectorID(URI.create("https:///path/a/b/c"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The URI must contain a host component", e.getMessage());
		}
	}


	public void testEnsureHTTPScheme() {

		try {
			SectorID.ensureHTTPScheme(URI.create("http://example.com/callbacks.json"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The URI must have a https scheme", e.getMessage());
		}
	}
}
