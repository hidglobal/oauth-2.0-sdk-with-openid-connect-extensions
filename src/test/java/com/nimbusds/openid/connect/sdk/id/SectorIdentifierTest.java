package com.nimbusds.openid.connect.sdk.id;


import java.net.URI;

import junit.framework.TestCase;


public class SectorIdentifierTest extends TestCase {
	

	public void testStringConstructor() {

		SectorIdentifier sectorIdentifier = new SectorIdentifier("example.com");
		assertEquals("example.com", sectorIdentifier.getValue());
	}


	public void testURIConstructor() {

		SectorIdentifier sectorIdentifier = new SectorIdentifier(URI.create("https://example.com"));
		assertEquals("example.com", sectorIdentifier.getValue());
	}


	public void testURIConstructor_missingHost() {

		try {
			new SectorIdentifier(URI.create("https:///path/a/b/c"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The URI must contain a host component", e.getMessage());
		}
	}
}
