package com.nimbusds.oauth2.sdk.token;


import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;


/**
 * Tests the bearer access token class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-19)
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
		assertEquals("bearer", json.get("token_type"));
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

		assertEquals(12, token.getValue().length());
		assertEquals(0l, token.getLifetime());
		assertNull(token.getScope());

		System.out.println(token.toAuthorizationHeader());
	}


	public void testGenerateDefault() {

		AccessToken token = new BearerAccessToken();

		assertNotNull(token);

		assertEquals(32, token.getValue().length());
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
		assertEquals("bearer", json.get("token_type"));
		assertEquals(1500l, json.get("expires_in"));
		assertTrue(Scope.parse((String)json.get("scope")).equals(scope));
		assertEquals(4, json.size());

		try {
			token = BearerAccessToken.parse(json);

		} catch (ParseException e) {

			fail(e.getMessage());
		}

		assertEquals("abc", json.get("access_token"));
		assertEquals("bearer", json.get("token_type"));
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
	
	
	public void testParseExceptionMissingBearerIdentifier() {
	
		AccessToken token = null;
	
		try {
			token = AccessToken.parse("abc");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
		
			// ok
			System.out.println(e.getMessage());
		}
	}
	
	
	public void testParseExceptionMissingTokenValue() {
	
		AccessToken token = null;
	
		try {
			token = AccessToken.parse("Bearer ");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
		
			// ok
			System.out.println(e.getMessage());
		}
	}
}
