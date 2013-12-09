package com.nimbusds.oauth2.sdk.id;


import junit.framework.TestCase;


/**
 * Tests the software ID class.
 */
public class SoftwareIDTest extends TestCase {


	public void testGenerateAndCompare() {

		SoftwareID id = new SoftwareID();

		System.out.println("Generated software ID: " + id);

		assertTrue(new SoftwareID(id.getValue()).equals(id));
	}
}
