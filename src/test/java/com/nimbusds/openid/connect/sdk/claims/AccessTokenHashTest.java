package com.nimbusds.openid.connect.sdk.claims;


import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;


/**
 * Tests the access token hash.
 *
 * @author Vladimir Dzhuvinov
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
}
