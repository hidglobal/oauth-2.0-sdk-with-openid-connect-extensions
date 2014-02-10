package com.nimbusds.oauth2.sdk.token;


import java.net.URL;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import org.apache.commons.codec.binary.Base64;


/**
 * Tests the bearer access token class.
 */
public class BearerAccessTokenTest extends TestCase {


	public void testMinimalConstructor() {
		
		AccessToken token = new BearerAccessToken("abc");
		
		assertEquals("abc", token.getValue());
		assertEquals(0l, token.getLifetime());
		assertNull(token.getScope());
		
		assertEquals("Bearer abc", token.toAuthorizationHeader());

		JSONObject json = token.toJSONObject();

		assertEquals("abc", json.get("access_token"));
		assertEquals("Bearer", json.get("token_type"));
		assertEquals(2, json.size());

		try {
			token = BearerAccessToken.parse(json);

		} catch (ParseException e) {

			fail(e.getMessage());
		}

		assertEquals("abc", token.getValue());
		assertEquals(0l, token.getLifetime());
		assertNull(token.getScope());
	}


	public void testGenerate() {

		AccessToken token = new BearerAccessToken(12);

		assertNotNull(token);

		assertEquals(12, Base64.decodeBase64(token.getValue()).length);
		assertEquals(0l, token.getLifetime());
		assertNull(token.getScope());

		System.out.println(token.toAuthorizationHeader());
	}


	public void testGenerateDefault() {

		AccessToken token = new BearerAccessToken();

		assertNotNull(token);

		assertEquals(32, Base64.decodeBase64(token.getValue()).length);
		assertEquals(0l, token.getLifetime());
		assertNull(token.getScope());

		System.out.println(token.toAuthorizationHeader());
	}


	public void testFullConstructor() {
		
		Scope scope = Scope.parse("read write");

		AccessToken token = new BearerAccessToken("abc", 1500, scope);
		
		assertEquals("abc", token.getValue());
		assertEquals(1500l, token.getLifetime());
		assertTrue(token.getScope().containsAll(Scope.parse("read write")));
		
		assertEquals("Bearer abc", token.toAuthorizationHeader());

		JSONObject json = token.toJSONObject();

		System.out.println(json);

		assertEquals("abc", json.get("access_token"));
		assertEquals("Bearer", json.get("token_type"));
		assertEquals(1500l, json.get("expires_in"));
		assertTrue(Scope.parse((String)json.get("scope")).equals(scope));
		assertEquals(4, json.size());

		try {
			BearerAccessToken.parse(json);

		} catch (ParseException e) {

			fail(e.getMessage());
		}

		assertEquals("abc", json.get("access_token"));
		assertEquals("Bearer", json.get("token_type"));
		assertEquals(1500l, json.get("expires_in"));
		assertTrue(Scope.parse((String)json.get("scope")).equals(scope));
		assertEquals(4, json.size());
	}
	
	
	public void testParse() {
	
		AccessToken token = null;
	
		try {
			token = AccessToken.parse("Bearer abc");
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals("abc", token.getValue());
		assertEquals(0l, token.getLifetime());
		assertNull(token.getScope());
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
