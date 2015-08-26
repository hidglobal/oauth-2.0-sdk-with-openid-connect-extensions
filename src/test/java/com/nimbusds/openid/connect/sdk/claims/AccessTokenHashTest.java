package com.nimbusds.openid.connect.sdk.claims;


import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;


/**
 * Tests the access token hash.
 */
public class AccessTokenHashTest extends TestCase {


	public void testComputeAgainstSpecExample()
		throws Exception {

		AccessToken token = new TypelessAccessToken("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y");

		AccessTokenHash computedHash = AccessTokenHash.compute(token, JWSAlgorithm.RS256);

		AccessTokenHash expectedHash = new AccessTokenHash("77QmUPtjPfzWtF2AnpK9RQ");

		assertEquals(expectedHash.getValue(), computedHash.getValue());
	}


	public void testEquality() {

		AccessToken token = new TypelessAccessToken("12345678");

		AccessTokenHash hash1 = AccessTokenHash.compute(token, JWSAlgorithm.HS512);

		AccessTokenHash hash2 = AccessTokenHash.compute(token, JWSAlgorithm.HS512);

		assertTrue(hash1.equals(hash2));
	}


	public void testUnsupportedJWSAlg() {

		AccessToken token = new TypelessAccessToken("12345678");

		assertNull(AccessTokenHash.compute(token, new JWSAlgorithm("no-such-alg")));
	}


	public void testIDTokenRequirement()
		throws Exception {

		// code flow
		// http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
		assertFalse(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("code")));

		// implicit flow
		// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken
		assertFalse(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("id_token")));
		assertTrue(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("id_token token")));

		// hybrid flow
		// http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
		assertFalse(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("code id_token")));
		assertFalse(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("code token")));
		assertTrue(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("code id_token token")));
	}
}
