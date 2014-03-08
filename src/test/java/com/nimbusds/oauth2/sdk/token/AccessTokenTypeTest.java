package com.nimbusds.oauth2.sdk.token;


import junit.framework.TestCase;


/**
 * Tests the access token type class.
 */
public class AccessTokenTypeTest extends TestCase {


	public void testEquality() {

		assertTrue(new AccessTokenType("bearer").equals(new AccessTokenType("bearer")));
		assertTrue(new AccessTokenType("Bearer").equals(new AccessTokenType("Bearer")));
		assertTrue(new AccessTokenType("Bearer").equals(new AccessTokenType("bearer")));
	}


	public void testInequality() {

		assertFalse(new AccessTokenType("bearer").equals(new AccessTokenType("mac")));
	}
}
