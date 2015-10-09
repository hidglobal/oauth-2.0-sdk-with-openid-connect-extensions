package com.nimbusds.oauth2.sdk.id;


import junit.framework.TestCase;


/**
 * Tests the client ID class.
 */
public class ClientIDTest extends TestCase {


	public void testIdentifierConstructor() {

		assertEquals("123", new ClientID(new Issuer("123")).getValue());
	}


	public void testEquality() {

		assertTrue(new ClientID("123").equals(new ClientID(new Issuer("123"))));
	}
}
