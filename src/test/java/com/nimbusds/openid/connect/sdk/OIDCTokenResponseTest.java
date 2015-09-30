package com.nimbusds.openid.connect.sdk;


import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;


/**
 * Tests the OpenID Connect token response.
 */
public class OIDCTokenResponseTest extends TestCase {


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


	public void testWithIDTokenJWT()
		throws Exception {

		OIDCTokens tokens = new OIDCTokens(ID_TOKEN, new BearerAccessToken("abc123"), new RefreshToken("def456"));

		OIDCTokenResponse response = new OIDCTokenResponse(tokens);

		assertTrue(response.indicatesSuccess());
		assertEquals("abc123", response.getOIDCTokens().getAccessToken().getValue());
		assertEquals("def456", response.getOIDCTokens().getRefreshToken().getValue());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDTokenString());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDToken().serialize());
		assertTrue(response.getCustomParams().isEmpty());

		HTTPResponse httpResponse = response.toHTTPResponse();

		response = OIDCTokenResponse.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals("abc123", response.getOIDCTokens().getAccessToken().getValue());
		assertEquals("def456", response.getOIDCTokens().getRefreshToken().getValue());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDTokenString());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDToken().serialize());
		assertTrue(response.getCustomParams().isEmpty());
	}


	public void testWithIDTokenJWTAndCustomParams()
		throws Exception {

		OIDCTokens tokens = new OIDCTokens(ID_TOKEN, new BearerAccessToken("abc123"), new RefreshToken("def456"));
		Map<String,Object> customParams = new HashMap<>();
		customParams.put("sub_sid", "abc");
		customParams.put("priority", 10);

		OIDCTokenResponse response = new OIDCTokenResponse(tokens, customParams);

		assertTrue(response.indicatesSuccess());
		assertEquals("abc123", response.getOIDCTokens().getAccessToken().getValue());
		assertEquals("def456", response.getOIDCTokens().getRefreshToken().getValue());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDTokenString());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDToken().serialize());
		assertEquals("abc", (String)response.getCustomParams().get("sub_sid"));
		assertEquals(10, ((Number)response.getCustomParams().get("priority")).intValue());
		assertEquals(2, response.getCustomParams().size());

		HTTPResponse httpResponse = response.toHTTPResponse();

		response = OIDCTokenResponse.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals("abc123", response.getOIDCTokens().getAccessToken().getValue());
		assertEquals("def456", response.getOIDCTokens().getRefreshToken().getValue());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDTokenString());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDToken().serialize());
		assertEquals("abc", (String)response.getCustomParams().get("sub_sid"));
		assertEquals(10, ((Number)response.getCustomParams().get("priority")).intValue());
		assertEquals(2, response.getCustomParams().size());
	}


	public void testWithIDTokenString()
		throws Exception {

		OIDCTokens tokens = new OIDCTokens(ID_TOKEN_STRING, new BearerAccessToken("abc123"), new RefreshToken("def456"));

		OIDCTokenResponse response = new OIDCTokenResponse(tokens);

		assertTrue(response.indicatesSuccess());
		assertEquals("abc123", response.getOIDCTokens().getAccessToken().getValue());
		assertEquals("def456", response.getOIDCTokens().getRefreshToken().getValue());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDTokenString());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDToken().serialize());
		assertTrue(response.getCustomParams().isEmpty());

		HTTPResponse httpResponse = response.toHTTPResponse();

		response = OIDCTokenResponse.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals("abc123", response.getOIDCTokens().getAccessToken().getValue());
		assertEquals("def456", response.getOIDCTokens().getRefreshToken().getValue());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDTokenString());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDToken().serialize());
		assertTrue(response.getCustomParams().isEmpty());
	}


	public void testWithIDTokenStringAndCustomParams()
		throws Exception {

		OIDCTokens tokens = new OIDCTokens(ID_TOKEN_STRING, new BearerAccessToken("abc123"), new RefreshToken("def456"));
		Map<String,Object> customParams = new HashMap<>();
		customParams.put("sub_sid", "abc");
		customParams.put("priority", 10);

		OIDCTokenResponse response = new OIDCTokenResponse(tokens, customParams);

		assertTrue(response.indicatesSuccess());
		assertEquals("abc123", response.getOIDCTokens().getAccessToken().getValue());
		assertEquals("def456", response.getOIDCTokens().getRefreshToken().getValue());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDTokenString());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDToken().serialize());
		assertEquals("abc", (String)response.getCustomParams().get("sub_sid"));
		assertEquals(10, ((Number)response.getCustomParams().get("priority")).intValue());
		assertEquals(2, response.getCustomParams().size());

		HTTPResponse httpResponse = response.toHTTPResponse();

		response = OIDCTokenResponse.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals("abc123", response.getOIDCTokens().getAccessToken().getValue());
		assertEquals("def456", response.getOIDCTokens().getRefreshToken().getValue());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDTokenString());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDToken().serialize());
		assertEquals("abc", (String)response.getCustomParams().get("sub_sid"));
		assertEquals(10, ((Number)response.getCustomParams().get("priority")).intValue());
		assertEquals(2, response.getCustomParams().size());
	}


	public void testWithInvalidIDTokenString()
		throws Exception {

		String invalidIDTokenString = "ey...";
		OIDCTokens tokens = new OIDCTokens(invalidIDTokenString, new BearerAccessToken("abc123"), new RefreshToken("def456"));
		OIDCTokenResponse response = new OIDCTokenResponse(tokens);

		assertTrue(response.indicatesSuccess());
		assertEquals("abc123", response.getOIDCTokens().getAccessToken().getValue());
		assertEquals("def456", response.getOIDCTokens().getRefreshToken().getValue());
		assertNull(response.getOIDCTokens().getIDToken());
		assertEquals(invalidIDTokenString, response.getOIDCTokens().getIDTokenString());

		JSONObject jsonObject = response.toJSONObject();

		try {
			OIDCTokenResponse.parse(jsonObject);
			fail();

		} catch (ParseException e) {
			// ok
		}
	}
}
