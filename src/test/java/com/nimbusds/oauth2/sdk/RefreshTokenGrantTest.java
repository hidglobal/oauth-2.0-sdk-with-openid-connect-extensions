package com.nimbusds.oauth2.sdk;


import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.token.RefreshToken;


/**
 * Tests the refresh token grant.
 */
public class RefreshTokenGrantTest extends TestCase {


	public void testConstructor() {

		RefreshToken refreshToken = new RefreshToken();
		RefreshTokenGrant grant = new RefreshTokenGrant(refreshToken);
		assertEquals(GrantType.REFRESH_TOKEN, grant.getType());
		assertEquals(refreshToken, grant.getRefreshToken());

		Map<String,String> params = grant.toParameters();
		assertEquals(GrantType.REFRESH_TOKEN.getValue(), params.get("grant_type"));
		assertEquals(refreshToken.getValue(), params.get("refresh_token"));
		assertEquals(2, params.size());
	}


	public void testParse()
		throws Exception {

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "refresh_token");
		params.put("refresh_token", "abc123");

		RefreshTokenGrant grant = RefreshTokenGrant.parse(params);
		assertEquals(GrantType.REFRESH_TOKEN, grant.getType());
		assertEquals("abc123", grant.getRefreshToken().getValue());
	}
}
