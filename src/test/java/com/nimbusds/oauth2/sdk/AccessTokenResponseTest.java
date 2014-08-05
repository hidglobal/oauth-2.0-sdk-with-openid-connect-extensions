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
import com.nimbusds.oauth2.sdk.token.TokenPair;


/**
 * Tests access token response serialisation and parsing.
 */
public class AccessTokenResponseTest extends TestCase {


	public void testConstructor() {

		AccessToken accessToken = new BearerAccessToken();
		RefreshToken refreshToken = new RefreshToken();

		AccessTokenResponse response = new AccessTokenResponse(accessToken, refreshToken);

		assertEquals(accessToken, response.getAccessToken());
		assertEquals(refreshToken, response.getRefreshToken());
		assertEquals(accessToken, response.getTokenPair().getAccessToken());
		assertEquals(refreshToken, response.getTokenPair().getRefreshToken());
		assertTrue(response.getCustomParams().isEmpty());
	}


	public void testConstructorMinimal() {

		AccessToken accessToken = new BearerAccessToken();

		AccessTokenResponse response = new AccessTokenResponse(accessToken, null);

		assertEquals(accessToken, response.getAccessToken());
		assertNull(response.getRefreshToken());
		assertEquals(accessToken, response.getTokenPair().getAccessToken());
		assertNull(response.getTokenPair().getRefreshToken());
		assertTrue(response.getCustomParams().isEmpty());
	}


	public void testConstructorWithCustomParams() {

		AccessToken accessToken = new BearerAccessToken();
		Map<String,Object> customParams = new HashMap<>();
		customParams.put("sub_sid", "abc");

		AccessTokenResponse response = new AccessTokenResponse(accessToken, null, customParams);

		assertEquals(accessToken, response.getAccessToken());
		assertNull(response.getRefreshToken());
		assertEquals(accessToken, response.getTokenPair().getAccessToken());
		assertNull(response.getTokenPair().getRefreshToken());
		assertEquals("abc", (String) response.getCustomParams().get("sub_sid"));
	}


	public void testAltConstructor() {

		AccessToken accessToken = new BearerAccessToken();
		RefreshToken refreshToken = new RefreshToken();
		TokenPair tokenPair = new TokenPair(accessToken, refreshToken);

		AccessTokenResponse response = new AccessTokenResponse(tokenPair);

		assertEquals(accessToken, response.getAccessToken());
		assertEquals(refreshToken, response.getRefreshToken());
		assertEquals(accessToken, response.getTokenPair().getAccessToken());
		assertEquals(refreshToken, response.getTokenPair().getRefreshToken());
		assertTrue(response.getCustomParams().isEmpty());
	}


	public void testAltConstructorMinimal() {

		AccessToken accessToken = new BearerAccessToken();
		TokenPair tokenPair = new TokenPair(accessToken, null);

		AccessTokenResponse response = new AccessTokenResponse(tokenPair);

		assertEquals(accessToken, response.getAccessToken());
		assertNull(response.getRefreshToken());
		assertEquals(accessToken, response.getTokenPair().getAccessToken());
		assertNull(response.getTokenPair().getRefreshToken());
		assertTrue(response.getCustomParams().isEmpty());
	}


	public void testAltConstructorWithCustomParams() {

		AccessToken accessToken = new BearerAccessToken();
		TokenPair tokenPair = new TokenPair(accessToken, null);
		Map<String,Object> customParams = new HashMap<>();
		customParams.put("sub_sid", "abc");

		AccessTokenResponse response = new AccessTokenResponse(tokenPair, customParams);
		assertEquals(accessToken, response.getAccessToken());
		assertNull(response.getRefreshToken());
		assertEquals(accessToken, response.getTokenPair().getAccessToken());
		assertNull(response.getTokenPair().getRefreshToken());
		assertEquals("abc", (String)response.getCustomParams().get("sub_sid"));
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

		AccessToken accessToken = atr.getAccessToken();
		assertEquals(accessTokenString, accessToken.getValue());
		assertEquals(exp, accessToken.getLifetime());
		assertNull(accessToken.getScope());

		RefreshToken refreshToken = atr.getRefreshToken();
		assertEquals(refreshTokenString, refreshToken.getValue());

		// Custom param
		assertEquals("abc", (String)atr.getCustomParams().get("sub_sid"));
		assertEquals(10, ((Number)atr.getCustomParams().get("priority")).intValue());
		assertEquals(2, atr.getCustomParams().size());

		// Test pair getter
		TokenPair pair = atr.getTokenPair();
		assertEquals(accessToken, pair.getAccessToken());
		assertEquals(refreshToken, pair.getRefreshToken());

		httpResponse = atr.toHTTPResponse();

		assertEquals(CommonContentTypes.APPLICATION_JSON, httpResponse.getContentType());
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

		AccessToken accessToken = atr.getAccessToken();
		assertEquals(accessTokenString, accessToken.getValue());
		assertNull(accessToken.getScope());

		// Test pair getter
		TokenPair pair = atr.getTokenPair();
		assertEquals(accessToken, pair.getAccessToken());

		httpResponse = atr.toHTTPResponse();

		assertEquals(CommonContentTypes.APPLICATION_JSON, httpResponse.getContentType());
		assertEquals("no-store", httpResponse.getCacheControl());
		assertEquals("no-cache", httpResponse.getPragma());

		o = httpResponse.getContentAsJSONObject();

		assertEquals(accessTokenString, o.get("access_token"));
		assertEquals("Bearer", o.get("token_type"));
	}
}
