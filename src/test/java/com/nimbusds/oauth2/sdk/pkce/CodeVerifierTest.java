package com.nimbusds.oauth2.sdk.pkce;


import junit.framework.TestCase;


/**
 * Code verifier test.
 */
public class CodeVerifierTest extends TestCase {


	public void testLengthLimitConstants() {

		assertEquals(43, CodeVerifier.MIN_LENGTH);
		assertEquals(128, CodeVerifier.MAX_LENGTH);
	}


	public void testDefaultConstructor() {

		CodeVerifier verifier = new CodeVerifier();
		assertEquals(43, verifier.getValue().length());
	}


	public void testEquality() {

		CodeVerifier verifier = new CodeVerifier();

		assertTrue(verifier.equals(new CodeVerifier(verifier.getValue())));
	}


	public void testInequality() {

		assertFalse(new CodeVerifier().equals(new CodeVerifier()));
		assertFalse(new CodeVerifier().equals(null));
	}
}
