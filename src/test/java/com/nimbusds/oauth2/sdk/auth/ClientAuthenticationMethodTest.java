package com.nimbusds.oauth2.sdk.auth;


import junit.framework.TestCase;


/**
 * Tests client authentication method class.
 */
public class ClientAuthenticationMethodTest extends TestCase {


	public void testConstants() {
	
		assertEquals("client_secret_basic", ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
		assertEquals("client_secret_post", ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue());
		assertEquals("client_secret_jwt", ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue());
		assertEquals("private_key_jwt", ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue());
		assertEquals("none", ClientAuthenticationMethod.NONE.getValue());
	}


	public void testGetDefault() {

		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, 
		             ClientAuthenticationMethod.getDefault());
	}


	public void testParse() {

		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.parse("client_secret_basic"));
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_POST, ClientAuthenticationMethod.parse("client_secret_post"));
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_JWT, ClientAuthenticationMethod.parse("client_secret_jwt"));
		assertEquals(ClientAuthenticationMethod.PRIVATE_KEY_JWT, ClientAuthenticationMethod.parse("private_key_jwt"));
		assertEquals(ClientAuthenticationMethod.NONE, ClientAuthenticationMethod.parse("none"));
	}


	public void testParseNull() {

		try {
			ClientAuthenticationMethod.parse(null);
			fail();
		} catch (NullPointerException e) {
			//  ok
		}
	}


	public void testParseEmptyValue() {

		try {
			ClientAuthenticationMethod.parse("");
			fail();
		} catch (IllegalArgumentException e) {
			// ok
		}
	}
}
