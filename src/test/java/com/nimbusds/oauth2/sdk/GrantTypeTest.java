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
		assertEquals("urn:ietf:params:oauth:grant-type:jwt-bearer", GrantType.JWT_BEARER.toString());
		assertEquals("urn:ietf:params:oauth:grant-type:saml2-bearer", GrantType.SAML2_BEARER.toString());
	}


	public void testClientAuthRequirement() {

		assertFalse(GrantType.AUTHORIZATION_CODE.requiresClientAuthentication());
		assertFalse(GrantType.IMPLICIT.requiresClientAuthentication());
		assertFalse(GrantType.REFRESH_TOKEN.requiresClientAuthentication());
		assertFalse(GrantType.PASSWORD.requiresClientAuthentication());
		assertTrue(GrantType.CLIENT_CREDENTIALS.requiresClientAuthentication());
		assertFalse(GrantType.JWT_BEARER.requiresClientAuthentication());
		assertFalse(GrantType.SAML2_BEARER.requiresClientAuthentication());
	}


	public void testClientIDRequirement() {

		assertTrue(GrantType.AUTHORIZATION_CODE.requiresClientID());
		assertTrue(GrantType.IMPLICIT.requiresClientID());
		assertFalse(GrantType.REFRESH_TOKEN.requiresClientID());
		assertFalse(GrantType.PASSWORD.requiresClientID());
		assertTrue(GrantType.CLIENT_CREDENTIALS.requiresClientID());
		assertFalse(GrantType.JWT_BEARER.requiresClientID());
		assertFalse(GrantType.SAML2_BEARER.requiresClientID());
	}


	public void testParse()
		throws ParseException {

		assertEquals(GrantType.AUTHORIZATION_CODE, GrantType.parse(GrantType.AUTHORIZATION_CODE.getValue()));
		assertEquals(GrantType.IMPLICIT, GrantType.parse(GrantType.IMPLICIT.getValue()));
		assertEquals(GrantType.REFRESH_TOKEN, GrantType.parse(GrantType.REFRESH_TOKEN.getValue()));
		assertEquals(GrantType.PASSWORD, GrantType.parse(GrantType.PASSWORD.getValue()));
		assertEquals(GrantType.CLIENT_CREDENTIALS, GrantType.parse(GrantType.CLIENT_CREDENTIALS.getValue()));
		assertEquals(GrantType.JWT_BEARER, GrantType.parse(GrantType.JWT_BEARER.getValue()));
		assertEquals(GrantType.SAML2_BEARER, GrantType.parse(GrantType.SAML2_BEARER.getValue()));
	}


	public void testParseUnsupported() {

		try {
			GrantType.parse("no-such-grant");
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE, e.getErrorObject());
		}
	}
}
