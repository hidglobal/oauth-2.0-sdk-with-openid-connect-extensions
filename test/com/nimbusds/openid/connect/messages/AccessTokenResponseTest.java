package com.nimbusds.openid.connect.messages;


import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWT;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.CommonContentTypes;
import com.nimbusds.openid.connect.http.HTTPResponse;


/**
 * Tests access token response serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-22)
 */
public class AccessTokenResponseTest extends TestCase {
	
	
	public void testAccessTokenResponseWithIDToken() {
	
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
		
		final String idTokenString = 
			"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOl" +
			"wvXC9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJ1c2VyX2lkIjoiMjQ4Mjg5NzYxMDAxIiwiYXVkIj" +
			"oiaHR0cDpcL1wvY2xpZW50LmV4YW1wbGUuY29tIiwiZXhwIjoxMzExMjgxOTcwfQ.eDesUD0" +
			"vzDH3T1G3liaTNOrfaeWYjuRCEPNXVtaazNQ";
		o.put("id_token", idTokenString);
		
		httpResponse.setContent(o.toString());
		
		
		AccessTokenResponse atr = null;
		
		try {
			atr = AccessTokenResponse.parse(httpResponse);
			
		} catch (ParseException e) {
			
			fail(e.getMessage());
		}
		
		AccessToken accessToken = atr.getAccessToken();
		assertEquals(accessTokenString, accessToken.getValue());
		assertEquals(exp, accessToken.getExpiration());
		assertNull(accessToken.getScope());
		
		JWT idToken = atr.getIDToken();
		assertNotNull(idToken);
		
		String serializedJWT = null;
		
		try {
			serializedJWT = idToken.serialize();
			// assertEquals(idTokenString, serializedJWT);
			
		} catch (IllegalStateException e) {
			
			fail(e.getMessage());
		}
		
		System.out.println(idToken.getClaimsSet().toJSONObject().toString());
		
		RefreshToken refreshToken = atr.getRefreshToken();
		assertEquals(refreshTokenString, refreshToken.getValue());
		
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
		assertEquals(serializedJWT, o.get("id_token"));
	}
}
