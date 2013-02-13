package com.nimbusds.oauth2.sdk;


import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.TokenPair;


/**
 * Tests access token response serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-02-13)
 */
public class AccessTokenResponseTest extends TestCase {
	
	
	public void testAccessTokenResponse() {
	
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
		
		httpResponse.setContent(o.toString());
		
		
		AccessTokenResponse atr = null;
		
		try {
			atr = AccessTokenResponse.parse(httpResponse);
			
		} catch (ParseException e) {
			
			fail(e.getMessage());
		}
		
		AccessToken accessToken = atr.getAccessToken();
		assertEquals(accessTokenString, accessToken.getValue());
		assertEquals(exp, accessToken.getLifetime());
		assertNull(accessToken.getScope());
		
		RefreshToken refreshToken = atr.getRefreshToken();
		assertEquals(refreshTokenString, refreshToken.getValue());

		// Test pair getter
		TokenPair pair = atr.getTokenPair();
		assertEquals(accessToken, pair.getAccessToken());
		assertEquals(refreshToken, pair.getRefreshToken());
		
		try {
			httpResponse = atr.toHTTPResponse();
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(CommonContentTypes.APPLICATION_JSON, httpResponse.getContentType());
		assertEquals("no-store", httpResponse.getCacheControl());
		assertEquals("no-cache", httpResponse.getPragma());
		
		try {
			o = httpResponse.getContentAsJSONObject();
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(accessTokenString, o.get("access_token"));
		assertEquals("Bearer", o.get("token_type"));
		assertEquals(refreshTokenString, o.get("refresh_token"));
		assertEquals(3600l, o.get("expires_in"));
	}
}
