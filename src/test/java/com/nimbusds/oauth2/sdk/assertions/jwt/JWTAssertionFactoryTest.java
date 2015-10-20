package com.nimbusds.oauth2.sdk.assertions.jwt;


import com.nimbusds.jose.JWSAlgorithm;
import junit.framework.TestCase;


/**
 * Tests the JWT assertion factory.
 */
public class JWTAssertionFactoryTest extends TestCase {


	public void testSupportedJWA() {

		assertTrue(JWTAssertionFactory.supportedJWAs().containsAll(JWSAlgorithm.Family.HMAC_SHA));
		assertTrue(JWTAssertionFactory.supportedJWAs().containsAll(JWSAlgorithm.Family.RSA));
		assertTrue(JWTAssertionFactory.supportedJWAs().containsAll(JWSAlgorithm.Family.EC));

		int algNum = JWSAlgorithm.Family.HMAC_SHA.size()
			+ JWSAlgorithm.Family.RSA.size()
			+ JWSAlgorithm.Family.EC.size();

		assertEquals(algNum, JWTAssertionFactory.supportedJWAs().size());
	}
}
