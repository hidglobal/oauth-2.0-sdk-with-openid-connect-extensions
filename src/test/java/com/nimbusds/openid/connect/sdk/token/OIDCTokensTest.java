package com.nimbusds.openid.connect.sdk.token;


import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;


/**
 * Tests the OpenID Connect tokens class.
 */
public class OIDCTokensTest extends TestCase {


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


	public void testAllDefined()
		throws ParseException {

		AccessToken accessToken = new BearerAccessToken(60l, Scope.parse("openid email"));
		RefreshToken refreshToken = new RefreshToken();

		OIDCTokens tokens = new OIDCTokens(ID_TOKEN, accessToken, refreshToken);

		assertEquals(ID_TOKEN, tokens.getIDToken());
		assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
		assertEquals(accessToken, tokens.getAccessToken());
		assertEquals(accessToken, tokens.getBearerAccessToken());
		assertEquals(refreshToken, tokens.getRefreshToken());

		assertTrue(tokens.getParameterNames().contains("id_token"));
		assertTrue(tokens.getParameterNames().contains("token_type"));
		assertTrue(tokens.getParameterNames().contains("access_token"));
		assertTrue(tokens.getParameterNames().contains("expires_in"));
		assertTrue(tokens.getParameterNames().contains("scope"));
		assertTrue(tokens.getParameterNames().contains("refresh_token"));
		assertEquals(6, tokens.getParameterNames().size());

		JSONObject jsonObject = tokens.toJSONObject();
		assertEquals(ID_TOKEN_STRING, jsonObject.get("id_token"));
		assertEquals("Bearer", jsonObject.get("token_type"));
		assertEquals(accessToken.getValue(), jsonObject.get("access_token"));
		assertEquals(60l, jsonObject.get("expires_in"));
		assertEquals("openid email", jsonObject.get("scope"));
		assertEquals(refreshToken.getValue(), jsonObject.get("refresh_token"));
		assertEquals(6, jsonObject.size());

		tokens = OIDCTokens.parse(jsonObject);

		assertEquals(ID_TOKEN.getParsedString(), tokens.getIDToken().getParsedString());
		assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
		assertEquals(accessToken.getValue(), tokens.getAccessToken().getValue());
		assertEquals(accessToken.getLifetime(), tokens.getAccessToken().getLifetime());
		assertEquals(accessToken.getScope(), tokens.getAccessToken().getScope());
		assertEquals(refreshToken.getValue(), tokens.getRefreshToken().getValue());
	}


	public void testAllDefined_fromIDTokenString()
		throws ParseException {

		AccessToken accessToken = new BearerAccessToken(60l, Scope.parse("openid email"));
		RefreshToken refreshToken = new RefreshToken();

		OIDCTokens tokens = new OIDCTokens(ID_TOKEN_STRING, accessToken, refreshToken);

		assertEquals(ID_TOKEN_STRING, tokens.getIDToken().getParsedString());
		assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
		assertEquals(accessToken, tokens.getAccessToken());
		assertEquals(accessToken, tokens.getBearerAccessToken());
		assertEquals(refreshToken, tokens.getRefreshToken());

		assertTrue(tokens.getParameterNames().contains("id_token"));
		assertTrue(tokens.getParameterNames().contains("token_type"));
		assertTrue(tokens.getParameterNames().contains("access_token"));
		assertTrue(tokens.getParameterNames().contains("expires_in"));
		assertTrue(tokens.getParameterNames().contains("scope"));
		assertTrue(tokens.getParameterNames().contains("refresh_token"));
		assertEquals(6, tokens.getParameterNames().size());

		JSONObject jsonObject = tokens.toJSONObject();
		assertEquals(ID_TOKEN_STRING, jsonObject.get("id_token"));
		assertEquals("Bearer", jsonObject.get("token_type"));
		assertEquals(accessToken.getValue(), jsonObject.get("access_token"));
		assertEquals(60l, jsonObject.get("expires_in"));
		assertEquals("openid email", jsonObject.get("scope"));
		assertEquals(refreshToken.getValue(), jsonObject.get("refresh_token"));
		assertEquals(6, jsonObject.size());

		tokens = OIDCTokens.parse(jsonObject);

		assertEquals(ID_TOKEN_STRING, tokens.getIDToken().getParsedString());
		assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
		assertEquals(accessToken.getValue(), tokens.getAccessToken().getValue());
		assertEquals(accessToken.getLifetime(), tokens.getAccessToken().getLifetime());
		assertEquals(accessToken.getScope(), tokens.getAccessToken().getScope());
		assertEquals(refreshToken.getValue(), tokens.getRefreshToken().getValue());
	}


	public void testMinimal()
		throws ParseException {

		AccessToken accessToken = new BearerAccessToken();

		OIDCTokens tokens = new OIDCTokens(ID_TOKEN, accessToken, null);

		assertEquals(ID_TOKEN, tokens.getIDToken());
		assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
		assertEquals(accessToken, tokens.getAccessToken());
		assertEquals(accessToken, tokens.getBearerAccessToken());
		assertNull(tokens.getRefreshToken());

		assertTrue(tokens.getParameterNames().contains("id_token"));
		assertTrue(tokens.getParameterNames().contains("token_type"));
		assertTrue(tokens.getParameterNames().contains("access_token"));
		assertEquals(3, tokens.getParameterNames().size());

		JSONObject jsonObject = tokens.toJSONObject();
		assertEquals(ID_TOKEN_STRING, jsonObject.get("id_token"));
		assertEquals("Bearer", jsonObject.get("token_type"));
		assertEquals(accessToken.getValue(), jsonObject.get("access_token"));
		assertEquals(3, jsonObject.size());

		tokens = OIDCTokens.parse(jsonObject);

		assertEquals(ID_TOKEN.getParsedString(), tokens.getIDToken().getParsedString());
		assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
		assertEquals(accessToken.getValue(), tokens.getAccessToken().getValue());
		assertEquals(0l, tokens.getAccessToken().getLifetime());
		assertNull(tokens.getAccessToken().getScope());
		assertNull(tokens.getRefreshToken());
	}


	public void testMinimal_fromIDTokenString()
		throws ParseException {

		AccessToken accessToken = new BearerAccessToken();

		OIDCTokens tokens = new OIDCTokens(ID_TOKEN_STRING, accessToken, null);

		assertEquals(ID_TOKEN_STRING, tokens.getIDToken().getParsedString());
		assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
		assertEquals(accessToken, tokens.getAccessToken());
		assertEquals(accessToken, tokens.getBearerAccessToken());
		assertNull(tokens.getRefreshToken());

		assertTrue(tokens.getParameterNames().contains("id_token"));
		assertTrue(tokens.getParameterNames().contains("token_type"));
		assertTrue(tokens.getParameterNames().contains("access_token"));
		assertEquals(3, tokens.getParameterNames().size());

		JSONObject jsonObject = tokens.toJSONObject();
		assertEquals(ID_TOKEN_STRING, jsonObject.get("id_token"));
		assertEquals("Bearer", jsonObject.get("token_type"));
		assertEquals(accessToken.getValue(), jsonObject.get("access_token"));
		assertEquals(3, jsonObject.size());

		tokens = OIDCTokens.parse(jsonObject);

		assertEquals(ID_TOKEN_STRING, tokens.getIDToken().getParsedString());
		assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
		assertEquals(accessToken.getValue(), tokens.getAccessToken().getValue());
		assertEquals(0l, tokens.getAccessToken().getLifetime());
		assertNull(tokens.getAccessToken().getScope());
		assertNull(tokens.getRefreshToken());
	}


	public void testMissingIDToken() {

		try {
			new OIDCTokens((JWT)null, new BearerAccessToken(), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The ID token must not be null", e.getMessage());
		}
	}


	public void testMissingIDTokenString() {

		try {
			new OIDCTokens((String)null, new BearerAccessToken(), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The ID token string must not be null", e.getMessage());
		}
	}


	public void testParseInvalidIDToken() {

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("id_token", "ey..."); // invalid
		jsonObject.put("token_type", "Bearer");
		jsonObject.put("access_token", "abc123");
		jsonObject.put("expires_in", 60l);

		try {
			OIDCTokens.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertTrue(e.getMessage().startsWith("Couldn't parse ID token: Invalid unsecured/JWS/JWE header:"));
		}
	}
}
