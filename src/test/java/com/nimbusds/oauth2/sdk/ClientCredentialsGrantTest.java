package com.nimbusds.oauth2.sdk;


import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;


/**
 * Tests the client credentials grant.
 */
public class ClientCredentialsGrantTest extends TestCase {


	public void testConstructor() {

		ClientCredentialsGrant grant = new ClientCredentialsGrant();
		assertEquals(GrantType.CLIENT_CREDENTIALS, grant.getType());

		Map<String,String> params = grant.toParameters();
		assertEquals("client_credentials", params.get("grant_type"));
		assertEquals(1, params.size());
	}


	public void testParse()
		throws Exception {

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "client_credentials");

		ClientCredentialsGrant grant = ClientCredentialsGrant.parse(params);
		assertEquals(GrantType.CLIENT_CREDENTIALS, grant.getType());
	}


	public void testParseMissingGrantType() {

		try {
			ClientCredentialsGrant.parse(new HashMap<String, String>());
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		}
	}


	public void testParseInvalidGrantType(){

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "invalid-grant");

		try {
			ClientCredentialsGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE, e.getErrorObject());
		}
	}
}
