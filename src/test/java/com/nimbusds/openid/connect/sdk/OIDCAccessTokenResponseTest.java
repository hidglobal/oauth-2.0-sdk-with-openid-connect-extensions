package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.ParseException;
import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;


/**
 * Tests the OpenID Connect access token response.
 *
 * @author Vladimir Dzhuvinov
 */
public class OIDCAccessTokenResponseTest extends TestCase {


	// Example ID token from OIDC Standard
	private static final String ID_TOKEN_STRING = "eyJhbGciOiJSUzI1NiJ9.ew0KICAgICJpc3MiOiAiaHR0cDovL"+
		"3NlcnZlci5leGFtcGxlLmNvbSIsDQogICAgInVzZXJfaWQiOiAiMjQ4Mjg5NzYxM"+
		"DAxIiwNCiAgICAiYXVkIjogInM2QmhkUmtxdDMiLA0KICAgICJub25jZSI6ICJuL"+
		"TBTNl9XekEyTWoiLA0KICAgICJleHAiOiAxMzExMjgxOTcwLA0KICAgICJpYXQiO"+
		"iAxMzExMjgwOTcwDQp9.lsQI_KNHpl58YY24G9tUHXr3Yp7OKYnEaVpRL0KI4szT"+
		"D6GXpZcgxIpkOCcajyDiIv62R9rBWASV191Akk1BM36gUMm8H5s8xyxNdRfBViCa"+
		"xTqHA7X_vV3U-tSWl6McR5qaSJaNQBpg1oGPjZdPG7zWCG-yEJC4-Fbx2FPOS7-h"+
		"5V0k33O5Okd-OoDUKoFPMd6ur5cIwsNyBazcsHdFHqWlCby5nl_HZdW-PHq0gjzy"+
		"JydB5eYIvOfOHYBRVML9fKwdOLM2xVxJsPwvy3BqlVKc593p2WwItIg52ILWrc6A"+
		"tqkqHxKsAXLVyAoVInYkl_NDBkCqYe2KgNJFzfEC8g";


	public static JWT ID_TOKEN;


	static {
		try {
			ID_TOKEN = JWTParser.parse(ID_TOKEN_STRING);
		} catch (Exception e) {
			ID_TOKEN = null;
		}
	}


	public void testMinimalConstructor()
		throws Exception {

		AccessToken accessToken = new BearerAccessToken("abc123");

		OIDCAccessTokenResponse response = new OIDCAccessTokenResponse(accessToken, null);

		assertEquals("abc123", response.getAccessToken().getValue());
		assertNull(response.getRefreshToken());
		assertNull(response.getIDToken());
		assertNull(response.getIDTokenString());

		HTTPResponse httpResponse = response.toHTTPResponse();

		response = OIDCAccessTokenResponse.parse(httpResponse);

		assertEquals("abc123", response.getAccessToken().getValue());
		assertNull(response.getRefreshToken());
		assertNull(response.getIDToken());
		assertNull(response.getIDTokenString());
	}


	public void testWithIDTokenJWT()
		throws Exception {

		AccessToken accessToken = new BearerAccessToken("abc123");
		RefreshToken refreshToken = new RefreshToken("def456");

		OIDCAccessTokenResponse response = new OIDCAccessTokenResponse(accessToken, refreshToken, ID_TOKEN);

		assertEquals("abc123", response.getAccessToken().getValue());
		assertEquals("def456", response.getRefreshToken().getValue());
		assertEquals(ID_TOKEN_STRING, response.getIDTokenString());
		assertEquals(ID_TOKEN_STRING, response.getIDToken().serialize());

		HTTPResponse httpResponse = response.toHTTPResponse();

		response = OIDCAccessTokenResponse.parse(httpResponse);

		assertEquals("abc123", response.getAccessToken().getValue());
		assertEquals("def456", response.getRefreshToken().getValue());
		assertEquals(ID_TOKEN_STRING, response.getIDTokenString());
		assertEquals(ID_TOKEN_STRING, response.getIDToken().serialize());
	}


	public void testWithIDTokenString()
		throws Exception {

		AccessToken accessToken = new BearerAccessToken("abc123");
		RefreshToken refreshToken = new RefreshToken("def456");

		OIDCAccessTokenResponse response = new OIDCAccessTokenResponse(accessToken, refreshToken, ID_TOKEN_STRING);

		assertEquals("abc123", response.getAccessToken().getValue());
		assertEquals("def456", response.getRefreshToken().getValue());
		assertEquals(ID_TOKEN_STRING, response.getIDTokenString());
		assertEquals(ID_TOKEN_STRING, response.getIDToken().serialize());

		HTTPResponse httpResponse = response.toHTTPResponse();

		response = OIDCAccessTokenResponse.parse(httpResponse);

		assertEquals("abc123", response.getAccessToken().getValue());
		assertEquals("def456", response.getRefreshToken().getValue());
		assertEquals(ID_TOKEN_STRING, response.getIDTokenString());
		assertEquals(ID_TOKEN_STRING, response.getIDToken().serialize());
	}


	public void testWithInvalidIDTokenString()
		throws Exception {

		AccessToken accessToken = new BearerAccessToken("abc123");
		RefreshToken refreshToken = new RefreshToken("def456");
		String invalidIDTokenString = "ey...";

		OIDCAccessTokenResponse response = new OIDCAccessTokenResponse(accessToken, refreshToken, invalidIDTokenString);

		assertEquals("abc123", response.getAccessToken().getValue());
		assertEquals("def456", response.getRefreshToken().getValue());
		assertNull(response.getIDToken());
		assertEquals(invalidIDTokenString, response.getIDTokenString());

		JSONObject jsonObject = response.toJSONObject();

		try {
			OIDCAccessTokenResponse.parse(jsonObject);
			fail("Failed to raise exception");

		} catch (ParseException e) {
			// ok
		}
	}
}
