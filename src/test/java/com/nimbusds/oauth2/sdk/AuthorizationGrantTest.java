package com.nimbusds.oauth2.sdk;


import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.id.ClientID;


/**
 * Tests the abstract authorisation grant class.
 */
public class AuthorizationGrantTest extends TestCase {
	
	
	public void testParse()
		throws Exception {
		
		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "authorization_code");
		params.put("code", "abc");
		params.put("client_id", "123");
		params.put("redirect_uri", "https://client.com/in");
		
		AuthorizationCodeGrant grant = (AuthorizationCodeGrant)AuthorizationGrant.parse(params);
		
		assertEquals(GrantType.AUTHORIZATION_CODE, grant.getType());
		assertEquals("abc", grant.getAuthorizationCode().getValue());
		assertEquals("123", grant.getClientID().getValue());
		assertEquals("https://client.com/in", grant.getRedirectionURI().toString());
	}
}
