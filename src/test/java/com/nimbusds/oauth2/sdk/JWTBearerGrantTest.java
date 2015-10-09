package com.nimbusds.oauth2.sdk;


import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.oauth2.sdk.auth.Secret;


/**
 * Tests the JWT bearer grant.
 */
public class JWTBearerGrantTest extends TestCase {


	public void testRejectUnsignedAssertion() {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		try {
			new JWTBearerGrant(new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet));
		} catch (IllegalArgumentException e) {
			assertEquals("The JWT assertion must not be in a unsigned state", e.getMessage());
		}
	}


	public void testConstructorAndParser()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		SignedJWT assertion = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

		assertion.sign(new MACSigner(new Secret().getValueBytes()));

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


	public void testParseInvalidGrantType()
		throws JOSEException {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		SignedJWT assertion = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		assertion.sign(new MACSigner(new Secret().getValueBytes()));

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "invalid-grant");
		params.put("assertion", assertion.serialize());

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


	public void testRejectPlainJWT() {

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", GrantType.JWT_BEARER.getValue());
		params.put("assertion", new PlainJWT(new JWTClaimsSet.Builder().subject("alice").build()).serialize());

		try {
			JWTBearerGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		}
	}
}
