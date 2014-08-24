package com.nimbusds.oauth2.sdk;


import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;


/**
 * Tests the authorisation code grant class.
 */
public class AuthorizationCodeGrantTest extends TestCase {


	public void testConstructor()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode("abc");
		URI redirectURI = new URI("https://client.com/in");

		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(code, redirectURI);

		assertEquals(code, grant.getAuthorizationCode());
		assertEquals(redirectURI, grant.getRedirectionURI());

		assertEquals(GrantType.AUTHORIZATION_CODE, grant.getType());

		Map<String,String> params = grant.toParameters();
		assertEquals("abc", params.get("code"));
		assertEquals("https://client.com/in", params.get("redirect_uri"));
		assertEquals("authorization_code", params.get("grant_type"));
		assertEquals(3, params.size());

		grant = AuthorizationCodeGrant.parse(params);
		assertEquals(code, grant.getAuthorizationCode());
		assertEquals(redirectURI, grant.getRedirectionURI());
		assertEquals(GrantType.AUTHORIZATION_CODE, grant.getType());
	}
	
	
	public void testParse()
		throws Exception {
		
		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "authorization_code");
		params.put("code", "abc");
		params.put("redirect_uri", "https://client.com/in");
		
		AuthorizationCodeGrant grant = AuthorizationCodeGrant.parse(params);
		
		assertEquals(GrantType.AUTHORIZATION_CODE, grant.getType());
		assertEquals("abc", grant.getAuthorizationCode().getValue());
		assertEquals("https://client.com/in", grant.getRedirectionURI().toString());
	}
}
