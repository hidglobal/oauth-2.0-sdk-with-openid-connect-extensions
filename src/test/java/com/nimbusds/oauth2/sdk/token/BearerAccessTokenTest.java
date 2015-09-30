package com.nimbusds.oauth2.sdk.token;


import java.net.URL;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.util.Base64;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;


/**
 * Tests the bearer access token class.
 */
public class BearerAccessTokenTest extends TestCase {


	public void testMinimalConstructor()
		throws Exception {
		
		AccessToken token = new BearerAccessToken("abc");
		
		assertEquals("abc", token.getValue());
		assertEquals(0l, token.getLifetime());
		assertNull(token.getScope());
		
		assertEquals("Bearer abc", token.toAuthorizationHeader());

		JSONObject json = token.toJSONObject();

		assertEquals("abc", json.get("access_token"));
		assertEquals("Bearer", json.get("token_type"));
		assertEquals(2, json.size());

		token = BearerAccessToken.parse(json);

		assertEquals("abc", token.getValue());
		assertEquals(0l, token.getLifetime());
		assertNull(token.getScope());

		assertTrue(token.getParamNames().contains("access_token"));
		assertTrue(token.getParamNames().contains("token_type"));
		assertEquals(2, token.getParamNames().size());
	}


	public void testGenerate() {

		AccessToken token = new BearerAccessToken(12);

		assertNotNull(token);

		assertEquals(12, new Base64(token.getValue()).decode().length);
		assertEquals(0l, token.getLifetime());
		assertNull(token.getScope());

		String header = token.toAuthorizationHeader();
		assertTrue(header.startsWith("Bearer "));
		assertEquals(token.getValue(), header.substring("Bearer ".length()));
	}


	public void testGenerateDefault() {

		AccessToken token = new BearerAccessToken();

		assertNotNull(token);

		assertEquals(32, new Base64(token.getValue()).decode().length);
		assertEquals(0l, token.getLifetime());
		assertNull(token.getScope());

		String header = token.toAuthorizationHeader();
		assertTrue(header.startsWith("Bearer "));
		assertEquals(token.getValue(), header.substring("Bearer ".length()));
	}


	public void testFullConstructor()
		throws Exception {
		
		Scope scope = Scope.parse("read write");

		AccessToken token = new BearerAccessToken("abc", 1500, scope);
		
		assertEquals("abc", token.getValue());
		assertEquals(1500l, token.getLifetime());
		assertTrue(token.getScope().containsAll(Scope.parse("read write")));
		
		assertEquals("Bearer abc", token.toAuthorizationHeader());

		JSONObject json = token.toJSONObject();

		assertEquals("abc", json.get("access_token"));
		assertEquals("Bearer", json.get("token_type"));
		assertEquals(1500l, json.get("expires_in"));
		assertTrue(Scope.parse((String)json.get("scope")).equals(scope));
		assertEquals(4, json.size());

		token = BearerAccessToken.parse(json);

		assertEquals("abc", json.get("access_token"));
		assertEquals("Bearer", json.get("token_type"));
		assertEquals(1500l, json.get("expires_in"));
		assertTrue(Scope.parse((String)json.get("scope")).equals(scope));
		assertEquals(4, json.size());

		assertTrue(token.getParamNames().contains("access_token"));
		assertTrue(token.getParamNames().contains("token_type"));
		assertTrue(token.getParamNames().contains("expires_in"));
		assertTrue(token.getParamNames().contains("scope"));
		assertEquals(4, token.getParamNames().size());
	}
	
	
	public void testParse()
		throws Exception {
	
		AccessToken token = AccessToken.parse("Bearer abc");
		
		assertEquals("abc", token.getValue());
		assertEquals(0l, token.getLifetime());
		assertNull(token.getScope());

		assertTrue(token.getParamNames().contains("access_token"));
		assertTrue(token.getParamNames().contains("token_type"));
		assertEquals(2, token.getParamNames().size());
	}


	public void testParseExceptionMissingAuthorizationHeader() {

		try {
			AccessToken.parse((String)null);

			fail();

		} catch (ParseException e) {

			assertEquals(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(BearerTokenError.MISSING_TOKEN.getCode(), e.getErrorObject().getCode());
		}
	}
	
	
	public void testParseExceptionMissingBearerIdentifier() {
	
		try {
			AccessToken.parse("abc");
			
			fail();
			
		} catch (ParseException e) {
		
			assertEquals(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(BearerTokenError.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
		}
	}
	
	
	public void testParseExceptionMissingTokenValue() {
	
		try {
			AccessToken.parse("Bearer ");
			
			fail();
			
		} catch (ParseException e) {

			assertEquals(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(BearerTokenError.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
		}
	}


	public void testParseFromHTTPRequest()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://c2id.com/reg/123"));
		httpRequest.setAuthorization("Bearer abc");

		BearerAccessToken accessToken = BearerAccessToken.parse(httpRequest);

		assertEquals("abc", accessToken.getValue());
	}


	public void testParseFromHTTPRequestMissing()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://c2id.com/reg/123"));

		try {
			BearerAccessToken.parse(httpRequest);
			fail();

		} catch (ParseException e) {

			assertEquals(401, e.getErrorObject().getHTTPStatusCode());
			assertNull(e.getErrorObject().getCode());
		}
	}


	public void testParseFromHTTPRequestInvalid()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://c2id.com/reg/123"));
		httpRequest.setAuthorization("Bearer");

		try {
			BearerAccessToken.parse(httpRequest);
			fail();

		} catch (ParseException e) {

			assertEquals(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(BearerTokenError.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
		}
	}
}
