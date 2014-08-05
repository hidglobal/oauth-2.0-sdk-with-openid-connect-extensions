package com.nimbusds.oauth2.sdk.token;


import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64;


/**
 * Tests the refresh token class.
 */
public class RefreshTokenTest extends TestCase {


	public void testValueConstructor() {

		RefreshToken rt = new RefreshToken("abc");
		assertEquals("abc", rt.getValue());
		assertTrue(rt.getParamNames().contains("refresh_token"));
		assertEquals(1, rt.getParamNames().size());
	}


	public void testGeneratorConstructor() {

		RefreshToken rt = new RefreshToken(16);
		assertEquals(16, new Base64(rt.getValue()).decode().length);
		assertTrue(rt.getParamNames().contains("refresh_token"));
		assertEquals(1, rt.getParamNames().size());
	}
}
