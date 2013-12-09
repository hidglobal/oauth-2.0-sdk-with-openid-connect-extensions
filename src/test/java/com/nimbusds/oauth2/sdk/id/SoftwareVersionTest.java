package com.nimbusds.oauth2.sdk.id;


import junit.framework.TestCase;


/**
 * Tests the software version class.
 */
public class SoftwareVersionTest extends TestCase {


	public void testConstructAndCompare() {

		SoftwareVersion version = new SoftwareVersion("1.0");

		assertTrue(new SoftwareVersion("1.0").equals(version));
	}
}
