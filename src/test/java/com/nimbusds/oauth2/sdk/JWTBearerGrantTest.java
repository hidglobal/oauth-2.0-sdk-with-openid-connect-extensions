package com.nimbusds.oauth2.sdk;


import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import com.nimbusds.oauth2.sdk.id.ClientID;


/**
 * Tests the JWT bearer grant.
 */
public class JWTBearerGrantTest extends TestCase {


	public void testMinimalConstructor()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setSubject("alice");

		JWT assertion = new PlainJWT(claimsSet);

		JWTBearerGrant grant = new JWTBearerGrant(assertion);

		assertEquals(GrantType.JWT_BEARER, grant.getType());
		assertEquals(assertion, grant.getJWTAssertion());
		assertEquals(assertion.serialize(), grant.getAssertion());
		assertNull(grant.getClientID());

		Map<String,String> params = grant.toParameters();
		assertEquals(GrantType.JWT_BEARER.getValue(), params.get("grant_type"));
		assertEquals(assertion.serialize(), params.get("assertion"));
		assertEquals(2, params.size());

		grant = JWTBearerGrant.parse(params);
		assertEquals(GrantType.JWT_BEARER, grant.getType());
		assertEquals(assertion.serialize(), grant.getAssertion());
		assertNull(grant.getClientID());
	}


	public void testFullConstructor()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setSubject("alice");

		JWT assertion = new PlainJWT(claimsSet);

		JWTBearerGrant grant = new JWTBearerGrant(assertion, new ClientID("123"));

		assertEquals(GrantType.JWT_BEARER, grant.getType());
		assertEquals(assertion, grant.getJWTAssertion());
		assertEquals(assertion.serialize(), grant.getAssertion());
		assertEquals("123", grant.getClientID().getValue());

		Map<String,String> params = grant.toParameters();
		assertEquals(GrantType.JWT_BEARER.getValue(), params.get("grant_type"));
		assertEquals(assertion.serialize(), params.get("assertion"));
		assertEquals("123", params.get("client_id"));
		assertEquals(3, params.size());

		grant = JWTBearerGrant.parse(params);
		assertEquals(GrantType.JWT_BEARER, grant.getType());
		assertEquals(assertion.serialize(), grant.getAssertion());
		assertEquals("123", grant.getClientID().getValue());
	}
}
