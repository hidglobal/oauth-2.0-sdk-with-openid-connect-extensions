package com.nimbusds.oauth2.sdk;


import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;


/**
 * Tests access token response serialisation and parsing.
 */
public class AccessTokenResponseTest extends TestCase {


	public void testConstructor()
		throws ParseException {

		Tokens tokens = new Tokens(new BearerAccessToken(), new RefreshToken());
		AccessTokenResponse response = new AccessTokenResponse(tokens);

		assertTrue(response.indicatesSuccess());
		assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
		assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
		assertEquals(tokens.getRefreshToken(), response.getTokens().getRefreshToken());
		assertTrue(response.getCustomParameters().isEmpty());
		assertTrue(response.getCustomParams().isEmpty());

		HTTPResponse httpResponse = response.toHTTPResponse();
		response = AccessTokenResponse.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
		assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
		assertEquals(tokens.getRefreshToken(), response.getTokens().getRefreshToken());
		assertTrue(response.getCustomParameters().isEmpty());
		assertTrue(response.getCustomParams().isEmpty());
	}


	public void testConstructorMinimal()
		throws ParseException {

		Tokens tokens = new Tokens(new BearerAccessToken(), null);

		AccessTokenResponse response = new AccessTokenResponse(tokens, null);

		assertTrue(response.indicatesSuccess());
		assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
		assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
		assertNull(response.getTokens().getRefreshToken());
		assertTrue(response.getCustomParameters().isEmpty());
		assertTrue(response.getCustomParams().isEmpty());

		HTTPResponse httpResponse = response.toHTTPResponse();
		response = AccessTokenResponse.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
		assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
		assertNull(response.getTokens().getRefreshToken());
		assertTrue(response.getCustomParameters().isEmpty());
		assertTrue(response.getCustomParams().isEmpty());
	}


	public void testConstructorWithCustomParams()
		throws ParseException {

		Tokens tokens = new Tokens(new BearerAccessToken(), null);
		Map<String,Object> customParams = new HashMap<>();
		customParams.put("sub_sid", "abc");

		AccessTokenResponse response = new AccessTokenResponse(tokens, customParams);

		assertTrue(response.indicatesSuccess());
		assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
		assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
		assertNull(response.getTokens().getRefreshToken());
		assertEquals("abc", (String) response.getCustomParameters().get("sub_sid"));
		assertEquals("abc", (String) response.getCustomParams().get("sub_sid"));

		HTTPResponse httpResponse = response.toHTTPResponse();
		response = AccessTokenResponse.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
		assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
		assertNull(response.getTokens().getRefreshToken());
		assertEquals("abc", (String) response.getCustomParameters().get("sub_sid"));
		assertEquals("abc", (String) response.getCustomParams().get("sub_sid"));
	}


	public void testParseFromHTTPResponseWithCustomParams()
		throws Exception {

		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");

		JSONObject o = new JSONObject();

		final String accessTokenString = "SlAV32hkKG";
		o.put("access_token", accessTokenString);

		o.put("token_type", "Bearer");

		final String refreshTokenString = "8xLOxBtZp8";
		o.put("refresh_token", refreshTokenString);

		final long exp = 3600;
		o.put("expires_in", exp);

		o.put("sub_sid", "abc");
		o.put("priority", 10);

		httpResponse.setContent(o.toString());


		AccessTokenResponse atr = AccessTokenResponse.parse(httpResponse);

		assertTrue(atr.indicatesSuccess());

		AccessToken accessToken = atr.getTokens().getAccessToken();
		assertEquals(accessTokenString, accessToken.getValue());

		BearerAccessToken bearerAccessToken = atr.getTokens().getBearerAccessToken();
		assertEquals(accessTokenString, bearerAccessToken.getValue());

		assertEquals(exp, accessToken.getLifetime());
		assertNull(accessToken.getScope());

		RefreshToken refreshToken = atr.getTokens().getRefreshToken();
		assertEquals(refreshTokenString, refreshToken.getValue());

		// Custom param
		assertEquals("abc", (String)atr.getCustomParameters().get("sub_sid"));
		assertEquals("abc", (String)atr.getCustomParams().get("sub_sid"));
		assertEquals(10, ((Number)atr.getCustomParameters().get("priority")).intValue());
		assertEquals(10, ((Number)atr.getCustomParams().get("priority")).intValue());
		assertEquals(2, atr.getCustomParameters().size());
		assertEquals(2, atr.getCustomParams().size());

		// Test pair getter
		Tokens pair = atr.getTokens();
		assertEquals(accessToken, pair.getAccessToken());
		assertEquals(refreshToken, pair.getRefreshToken());

		httpResponse = atr.toHTTPResponse();

		assertEquals(CommonContentTypes.APPLICATION_JSON.toString(), httpResponse.getContentType().toString());
		assertEquals("no-store", httpResponse.getCacheControl());
		assertEquals("no-cache", httpResponse.getPragma());

		o = httpResponse.getContentAsJSONObject();

		assertEquals(accessTokenString, o.get("access_token"));
		assertEquals("Bearer", o.get("token_type"));
		assertEquals(refreshTokenString, o.get("refresh_token"));
		assertEquals(3600l, o.get("expires_in"));

		// Custom param
		assertEquals("abc", (String)o.get("sub_sid"));
		assertEquals(10, ((Number)o.get("priority")).intValue());
	}


	public void testParseFromAltHTTPResponse()
		throws Exception {

		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");

		JSONObject o = new JSONObject();

		final String accessTokenString = "SlAV32hkKG";
		o.put("access_token", accessTokenString);

		o.put("token_type", "bearer");

		httpResponse.setContent(o.toString());

		AccessTokenResponse atr = AccessTokenResponse.parse(httpResponse);

		assertTrue(atr.indicatesSuccess());
		AccessToken accessToken = atr.getTokens().getAccessToken();
		assertEquals(accessTokenString, accessToken.getValue());
		BearerAccessToken bearerAccessToken = atr.getTokens().getBearerAccessToken();
		assertEquals(accessTokenString, bearerAccessToken.getValue());
		assertNull(accessToken.getScope());

		Tokens tokens = atr.getTokens();
		assertEquals(accessToken, tokens.getAccessToken());

		httpResponse = atr.toHTTPResponse();

		assertEquals(CommonContentTypes.APPLICATION_JSON.toString(), httpResponse.getContentType().toString());
		assertEquals("no-store", httpResponse.getCacheControl());
		assertEquals("no-cache", httpResponse.getPragma());

		o = httpResponse.getContentAsJSONObject();

		assertEquals(accessTokenString, o.get("access_token"));
		assertEquals("Bearer", o.get("token_type"));
	}
}
