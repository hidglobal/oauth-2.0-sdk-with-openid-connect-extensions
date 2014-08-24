package com.nimbusds.oauth2.sdk;


import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;


/**
 * Tests the JWT bearer grant.
 */
public class JWTBearerGrantTest extends TestCase {


	public void testConstructorAndParser()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setSubject("alice");

		JWT assertion = new PlainJWT(claimsSet);

		JWTBearerGrant grant = new JWTBearerGrant(assertion);

		assertEquals(GrantType.JWT_BEARER, grant.getType());
		assertEquals(assertion, grant.getJWTAssertion());
		assertEquals(assertion.serialize(), grant.getAssertion());

		Map<String,String> params = grant.toParameters();
		assertEquals(GrantType.JWT_BEARER.getValue(), params.get("grant_type"));
		assertEquals(assertion.serialize(), params.get("assertion"));
		assertEquals(2, params.size());

		grant = JWTBearerGrant.parse(params);
		assertEquals(GrantType.JWT_BEARER, grant.getType());
		assertEquals(assertion.serialize(), grant.getAssertion());
	}


	public void testParseInvalidGrant() {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setSubject("alice");

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "invalid-grant");
		params.put("assertion", new PlainJWT(claimsSet).serialize());

		try {
			JWTBearerGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE, e.getErrorObject());
		}
	}


	public void testParseMissingAssertion() {

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", GrantType.JWT_BEARER.getValue());

		try {
			JWTBearerGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		}
	}


	public void testParseInvalidJWTAssertion() {

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", GrantType.JWT_BEARER.getValue());
		params.put("assertion", "invalid-jwt");

		try {
			JWTBearerGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		}
	}
}
