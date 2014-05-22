package com.nimbusds.oauth2.sdk;


import junit.framework.TestCase;


/**
 * Tests the grant type class.
 */
public class GrantTypeTest extends TestCase {


	public void testConstants() {

		assertEquals("authorization_code", GrantType.AUTHORIZATION_CODE.toString());

		assertEquals("implicit", GrantType.IMPLICIT.toString());

		assertEquals("refresh_token", GrantType.REFRESH_TOKEN.toString());

		assertEquals("password", GrantType.PASSWORD.toString());

		assertEquals("client_credentials", GrantType.CLIENT_CREDENTIALS.toString());
	}


	public void testConstructors() {

		GrantType grantType = new GrantType("x_custom");

		assertEquals("x_custom", grantType.getValue());
	}
	
	
	public void testEquality() {
	
		assertTrue(new GrantType("authorization_code").equals(GrantType.AUTHORIZATION_CODE));
		assertTrue(new GrantType("implicit").equals(GrantType.IMPLICIT));
		assertTrue(new GrantType("refresh_token").equals(GrantType.REFRESH_TOKEN));
		assertTrue(new GrantType("password").equals(GrantType.PASSWORD));
		assertTrue(new GrantType("client_credentials").equals(GrantType.CLIENT_CREDENTIALS));
		
		assertTrue(new GrantType("x_custom").equals(new GrantType("x_custom")));
	}
	
	
	public void testInequality() {
	
		assertFalse(new GrantType("a").equals(new GrantType("b")));
	}
}
