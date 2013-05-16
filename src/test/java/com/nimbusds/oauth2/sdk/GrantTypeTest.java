package com.nimbusds.oauth2.sdk;


import junit.framework.TestCase;


/**
 * Tests the grant type class.
 *
 * @author Vladimir Dzhuvinov
 */
public class GrantTypeTest extends TestCase {


	public void testConstants() {

		assertEquals("authorization_code", GrantType.AUTHORIZATION_CODE.toString());

		assertEquals("refresh_token", GrantType.REFRESH_TOKEN.toString());

		assertEquals("password", GrantType.PASSWORD.toString());

		assertEquals("client_credentials", GrantType.CLIENT_CREDENTIALS.toString());
	}
}
