package com.nimbusds.oauth2.sdk.token;


import junit.framework.TestCase;


/**
 * Tests the token encoding enumeration.
 */
public class TokenEncodingTest extends TestCase {


	public void testNames() {

		assertEquals("IDENTIFIER", TokenEncoding.IDENTIFIER.toString());
		assertEquals("SELF_CONTAINED", TokenEncoding.SELF_CONTAINED.toString());

		assertEquals(2, TokenEncoding.values().length);
	}
}
