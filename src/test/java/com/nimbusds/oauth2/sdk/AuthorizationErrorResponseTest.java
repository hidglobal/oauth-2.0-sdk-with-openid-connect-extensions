package com.nimbusds.oauth2.sdk;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Tests authorisation error response serialisation and parsing.
 */
public class AuthorizationErrorResponseTest extends TestCase {
	
	
	private static URI REDIRECT_URI = null;
	
	
	private static URI ERROR_PAGE_URL = null;
	
	
	public void setUp()
		throws URISyntaxException {
		
		REDIRECT_URI = new URI("https://client.example.com/cb");
		
		ERROR_PAGE_URL = new URI("http://server.example.com/error/123");
	}


	public void testStandardErrors() {
	
		Set<ErrorObject> errors = AuthorizationErrorResponse.getStandardErrors();
	
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
	
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		State state = new State("xyz");
	
		AuthorizationErrorResponse r = new AuthorizationErrorResponse(REDIRECT_URI,
		                                                              OAuth2Error.INVALID_REQUEST,
									      rts,
									      state);

		assertEquals(REDIRECT_URI, r.getRedirectionURI());
		assertEquals(OAuth2Error.INVALID_REQUEST, r.getErrorObject());
		assertEquals(rts, r.getResponseType());
		assertEquals(state, r.getState());

		Map<String,String> params = r.toParameters();
		assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), params.get("error"));
		assertEquals(OAuth2Error.INVALID_REQUEST.getDescription(), params.get("error_description"));
		assertNull(params.get("error_uri"));
		assertEquals(state.toString(), params.get("state"));
		assertEquals(3, params.size());

		URI location = r.toURI();
			
		System.out.println(location.toString());
		assertNull(location.getFragment());
		assertNotNull(location.getQuery());
			
		assertEquals(REDIRECT_URI.getScheme(), location.getScheme());
		assertEquals(REDIRECT_URI.getPort(), location.getPort());
		assertEquals(REDIRECT_URI.getHost(), location.getHost());
		assertEquals(REDIRECT_URI.getPath(), location.getPath());
			
		params = URLUtils.parseParameters(location.getQuery());
			
		assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), params.get("error"));
		assertEquals(OAuth2Error.INVALID_REQUEST.getDescription(), params.get("error_description"));
		assertEquals(state.toString(), params.get("state"));
		assertEquals(3, params.size());
			
		HTTPResponse httpResponse = r.toHTTPResponse();
			
		assertEquals(HTTPResponse.SC_FOUND, httpResponse.getStatusCode());
		assertEquals(location, httpResponse.getLocation());

		r = AuthorizationErrorResponse.parse(httpResponse);

		assertEquals(REDIRECT_URI, r.getRedirectionURI());
		assertEquals(OAuth2Error.INVALID_REQUEST, r.getErrorObject());
		assertNull(r.getResponseType());
		assertEquals(state, r.getState());
	}


	public void testCodeErrorResponse()
		throws Exception {

		URI redirectURI = new URI("https://client.com/cb");
		ErrorObject error = OAuth2Error.ACCESS_DENIED;
		ResponseType responseType = new ResponseType("code");
		State state = new State();

		AuthorizationErrorResponse response = new AuthorizationErrorResponse(
			redirectURI, error, responseType, state);

		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertEquals(responseType, response.getResponseType());
		assertEquals(state, response.getState());

		URI responseURI = response.toURI();

		assertNotNull(responseURI.getQuery());
		assertNull(responseURI.getFragment());

		response = AuthorizationErrorResponse.parse(responseURI);

		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertNull(response.getResponseType());
		assertEquals(state, response.getState());
	}


	public void testTokenErrorResponse()
		throws Exception {

		URI redirectURI = new URI("https://client.com/cb");
		ErrorObject error = OAuth2Error.ACCESS_DENIED;
		ResponseType responseType = new ResponseType("token");
		State state = new State();

		AuthorizationErrorResponse response = new AuthorizationErrorResponse(
			redirectURI, error, responseType, state);

		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertEquals(responseType, response.getResponseType());
		assertEquals(state, response.getState());

		URI responseURI = response.toURI();

		assertNull(responseURI.getQuery());
		assertNotNull(responseURI.getFragment());

		response = AuthorizationErrorResponse.parse(responseURI);

		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertNull(response.getResponseType());
		assertEquals(state, response.getState());
	}
	
	
	public void testParse()
		throws URISyntaxException {
	
		String s = "https://client.example.com/cb?error=invalid_request&error_description=Invalid+request&error_uri=http%3A%2F%2Fserver.example.com%2Ferror%2F123&state=123";

		AuthorizationErrorResponse r = null;
		
		try {
			r = AuthorizationErrorResponse.parse(new URI(s));
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals("https://client.example.com/cb", r.getRedirectionURI().toString());
		assertEquals(OAuth2Error.INVALID_REQUEST, r.getErrorObject());
		assertEquals(ERROR_PAGE_URL, r.getErrorObject().getURI());
		assertEquals(new State("123"), r.getState());
		
		assertNull(r.getResponseType());
	}
	
	
	public void testParseExceptions()
		throws URISyntaxException {
		
		String s1 = "https://client.example.com/cb";
		
		try {
			AuthorizationErrorResponse.parse(new URI(s1));
			fail();
			
		} catch (ParseException e) {
			// ok
		}
	}
}
