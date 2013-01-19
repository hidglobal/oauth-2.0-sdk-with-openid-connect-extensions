package com.nimbusds.oauth2.sdk;


import java.net.MalformedURLException;
import java.net.URL;

import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import com.nimbusds.oauth2.sdk.id.State;

import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Tests authorisation error response serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-19)
 */
public class AuthorizationErrorResponseTest extends TestCase {
	
	
	private static URL REDIRECT_URL = null;
	
	
	private static URL ERROR_PAGE_URL = null;
	
	
	public void setUp()
		throws MalformedURLException {
		
		REDIRECT_URL = new URL("https://client.example.com/cb");
		
		ERROR_PAGE_URL = new URL("http://server.example.com/error/123");
	}


	public void testStandardErrors() {
	
		Set<OAuth2Error> errors = AuthorizationErrorResponse.getStandardErrors();
	
		assertTrue(errors.contains(OAuth2Error.INVALID_REQUEST));
		assertTrue(errors.contains(OAuth2Error.UNAUTHORIZED_CLIENT));
		assertTrue(errors.contains(OAuth2Error.ACCESS_DENIED));
		assertTrue(errors.contains(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE));
		assertTrue(errors.contains(OAuth2Error.INVALID_SCOPE));
		assertTrue(errors.contains(OAuth2Error.SERVER_ERROR));
		assertTrue(errors.contains(OAuth2Error.TEMPORARILY_UNAVAILABLE));
		
		assertEquals(7, errors.size());
	}
	
	
	public void testSerializeAndParse()
		throws Exception {
	
		ResponseTypeSet rts = new ResponseTypeSet();
		rts.add(ResponseType.CODE);

		State state = new State("xyz");
	
		AuthorizationErrorResponse r = new AuthorizationErrorResponse(REDIRECT_URL, 
		                                                              OAuth2Error.INVALID_REQUEST,
									      rts,
									      state);

		assertEquals(REDIRECT_URL, r.getRedirectURI());
		assertEquals(OAuth2Error.INVALID_REQUEST, r.getError());
		assertEquals(rts, r.getResponseTypeSet());
		assertEquals(state, r.getState());

		Map<String,String> params = r.toParameters();
		assertEquals(OAuth2Error.INVALID_REQUEST.getValue(), params.get("error"));
		assertEquals(OAuth2Error.INVALID_REQUEST.getDescription(), params.get("error_description"));
		assertNull(params.get("error_uri"));
		assertEquals(state.toString(), params.get("state"));
		assertEquals(3, params.size());

		URL location = r.toURI();
			
		System.out.println(location.toString());
		assertNull(location.getRef());
		assertNotNull(location.getQuery());
			
		assertEquals(REDIRECT_URL.getProtocol(), location.getProtocol());
		assertEquals(REDIRECT_URL.getPort(), location.getPort());
		assertEquals(REDIRECT_URL.getHost(), location.getHost());
		assertEquals(REDIRECT_URL.getPath(), location.getPath());
			
		params = URLUtils.parseParameters(location.getQuery());
			
		assertEquals(OAuth2Error.INVALID_REQUEST.getValue(), params.get("error"));
		assertEquals(OAuth2Error.INVALID_REQUEST.getDescription(), params.get("error_description"));
		assertEquals(state.toString(), params.get("state"));
		assertEquals(3, params.size());
			
		HTTPResponse httpResponse = r.toHTTPResponse();
			
		assertEquals(HTTPResponse.SC_FOUND, httpResponse.getStatusCode());
		assertEquals(location, httpResponse.getLocation());

		r = AuthorizationErrorResponse.parse(httpResponse);

		assertEquals(REDIRECT_URL, r.getRedirectURI());
		assertEquals(OAuth2Error.INVALID_REQUEST, r.getError());
		assertNull(r.getResponseTypeSet());
		assertEquals(state, r.getState());
	}
	
	
	public void testParse()
		throws MalformedURLException {
	
		String s = "https://client.example.com/cb?error=invalid_request&error_description=Invalid+request&error_uri=http%3A%2F%2Fserver.example.com%2Ferror%2F123&state=123";

		AuthorizationErrorResponse r = null;
		
		try {
			r = AuthorizationErrorResponse.parse(new URL(s));
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals("https://client.example.com/cb", r.getRedirectURI().toString());
		assertEquals(OAuth2Error.INVALID_REQUEST, r.getError());
		assertEquals(ERROR_PAGE_URL, r.getError().getURI());
		assertEquals(new State("123"), r.getState());
		
		assertNull(r.getResponseTypeSet());
	}
	
	
	public void testParseExceptions()
		throws MalformedURLException {
		
		String s1 = "https://client.example.com/cb";
		
		try {
			AuthorizationErrorResponse.parse(new URL(s1));
			fail("Failed to raise exception: No params");
			
		} catch (ParseException e) {
		
			System.out.println(e);
		}
		
		
		String s2 = "https://client.example.com/cb?error=invalid_request&error_uri=example.html";
		
		try {
			AuthorizationErrorResponse.parse(new URL(s2));
			fail("Failed to raise exception: Invalid error URI");
			
		} catch (ParseException e) {
		
			System.out.println(e);
		}
	}
}
