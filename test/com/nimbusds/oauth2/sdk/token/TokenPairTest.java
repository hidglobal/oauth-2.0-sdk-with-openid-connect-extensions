package com.nimbusds.oauth2.sdk.token;


import junit.framework.TestCase;


/**
 * Tests the token pair class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-02-13)
 */
public class TokenPairTest extends TestCase {


	public void testConstructorAllDefined() {

		AccessToken accessToken = new BearerAccessToken();
		RefreshToken refreshToken = new RefreshToken();

		TokenPair pair = new TokenPair(accessToken, refreshToken);

		assertEquals(accessToken, pair.getAccessToken());
		assertEquals(refreshToken, pair.getRefreshToken());

		System.out.println(pair);
	}


	public void testConstructorAccessTokenOnly() {

		AccessToken accessToken = new BearerAccessToken();

		TokenPair pair = new TokenPair(accessToken, null);

		assertEquals(accessToken, pair.getAccessToken());
		assertNull(pair.getRefreshToken());

		System.out.println(pair);
	}


	public void testMissingAccessTokenException() {

		try {
			TokenPair pair = new TokenPair(null, null);

			fail("Failed to raise exception");

		} catch (IllegalArgumentException e) {

			// ok
		}
	}
}