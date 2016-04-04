package com.nimbusds.oauth2.sdk.pkce;


import junit.framework.TestCase;


/**
 * Code challenge methods test.
 */
public class CodeChallengeMethodTest extends TestCase {
	

	public void testConstants() {

		assertEquals("plain", CodeChallengeMethod.PLAIN.getValue());
		assertEquals("S256", CodeChallengeMethod.S256.getValue());
	}


	public void testDefault() {

		assertTrue(CodeChallengeMethod.PLAIN.equals(CodeChallengeMethod.getDefault()));
	}


	public void testParse() {

		assertTrue(CodeChallengeMethod.PLAIN.equals(CodeChallengeMethod.parse("plain")));
		assertTrue(CodeChallengeMethod.S256.equals(CodeChallengeMethod.parse("S256")));
		assertTrue(new CodeChallengeMethod("S512").equals(CodeChallengeMethod.parse("S512")));
	}


	public void testParseEquality() {

		assertTrue(CodeChallengeMethod.parse("plain") == CodeChallengeMethod.PLAIN);
		assertTrue(CodeChallengeMethod.parse("S256") == CodeChallengeMethod.S256);
	}
}
