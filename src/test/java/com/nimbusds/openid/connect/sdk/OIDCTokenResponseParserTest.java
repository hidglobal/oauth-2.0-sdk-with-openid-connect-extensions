package com.nimbusds.openid.connect.sdk;


import junit.framework.TestCase;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;


/**
 * Tests the OpenID Connect token response parser.
 */
public class OIDCTokenResponseParserTest extends TestCase {


	// Example ID token from OIDC Standard
	private static final String ID_TOKEN_STRING =
		"eyJhbGciOiJSUzI1NiJ9.ew0KICAgICJpc3MiOiAiaHR0cDovL"+
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


	public void testParseSuccess()
		throws Exception {

		OIDCTokens tokens = new OIDCTokens(
			ID_TOKEN,
			new BearerAccessToken("abc123"),
			new RefreshToken("def456"));

		OIDCTokenResponse response = new OIDCTokenResponse(tokens);

		assertEquals(tokens, response.getOIDCTokens());
		assertEquals(tokens, response.getTokens());

		HTTPResponse httpResponse = response.toHTTPResponse();

		TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);

		assertTrue(tokenResponse.indicatesSuccess());

		assertTrue(tokenResponse instanceof OIDCTokenResponse);

		response = (OIDCTokenResponse)tokenResponse;

		assertEquals("abc123", response.getTokens().getAccessToken().getValue());
		assertEquals("def456", response.getTokens().getRefreshToken().getValue());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDTokenString());
		assertEquals(ID_TOKEN_STRING, response.getOIDCTokens().getIDToken().serialize());
	}


	public void testParseError()
		throws Exception {

		TokenErrorResponse response = new TokenErrorResponse(OAuth2Error.INVALID_GRANT);

		HTTPResponse httpResponse = response.toHTTPResponse();

		TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);

		assertFalse(tokenResponse.indicatesSuccess());
		assertTrue(tokenResponse instanceof TokenErrorResponse);
		response = (TokenErrorResponse)tokenResponse;
		assertEquals(OAuth2Error.INVALID_GRANT, response.getErrorObject());
	}
}
