package com.nimbusds.oauth2.sdk;


import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;


/**
 * Tests the abstract authorisation grant class.
 */
public class AuthorizationGrantTest extends TestCase {
	
	
	public void testParseCode()
		throws Exception {
		
		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "authorization_code");
		params.put("code", "abc");
		params.put("redirect_uri", "https://client.com/in");
		
		AuthorizationCodeGrant grant = (AuthorizationCodeGrant)AuthorizationGrant.parse(params);
		
		assertEquals(GrantType.AUTHORIZATION_CODE, grant.getType());
		assertEquals("abc", grant.getAuthorizationCode().getValue());
		assertEquals("https://client.com/in", grant.getRedirectionURI().toString());
	}


	public void testParseJWTBearer()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setSubject("alice");

		JWT assertion = new PlainJWT(claimsSet);

		JWTBearerGrant grant = new JWTBearerGrant(assertion);

		Map<String,String> params = grant.toParameters();

		grant = (JWTBearerGrant)AuthorizationGrant.parse(params);

		assertEquals(GrantType.JWT_BEARER, grant.getType());
		assertEquals(assertion.serialize(), grant.getAssertion());
	}
}
