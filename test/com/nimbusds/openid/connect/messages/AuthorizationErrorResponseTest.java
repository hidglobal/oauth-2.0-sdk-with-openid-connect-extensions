package com.nimbusds.openid.connect.messages;


import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.HTTPResponse;

import com.nimbusds.openid.connect.util.URLUtils;


/**
 * Tests authorisation error response serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.2 (2012-05-03)
 */
public class AuthorizationErrorResponseTest extends TestCase {
	
	
	private static URL REDIRECT_URL = null;
	
	
	private static URL ERROR_PAGE_URL = null;
	
	
	public void setUp()
		throws MalformedURLException {
		
		REDIRECT_URL = new URL("https://client.example.com/cb");
		
		ERROR_PAGE_URL = new URL("http://server.example.com/error/123");
	}
	
	
	public void testConstructorMinimal() {
	
		ResponseTypeSet rts = new ResponseTypeSet();
		rts.add(ResponseType.CODE);
	
		AuthorizationErrorResponse r = new AuthorizationErrorResponse(REDIRECT_URL, 
		                                                              ErrorCode.INVALID_REQUEST,
									      null,
									      rts,
									      null);

		assertEquals(ErrorCode.INVALID_REQUEST, r.getErrorCode());
		assertNull(r.getErrorURI());
		assertNotNull(r.getResponseTypeSet());
		assertEquals(1, r.getResponseTypeSet().size());
		assertTrue(r.getResponseTypeSet().contains(ResponseType.CODE));
		assertNull(r.getState());
		
		try {
			URL location = r.toURL();
			
			System.out.println(location.toString());
			
			assertNull(location.getRef());
			assertNotNull(location.getQuery());
			
			assertEquals(REDIRECT_URL.getProtocol(), location.getProtocol());
			assertEquals(REDIRECT_URL.getPort(), location.getPort());
			assertEquals(REDIRECT_URL.getHost(), location.getHost());
			assertEquals(REDIRECT_URL.getPath(), location.getPath());
			
			Map<String,String> params = URLUtils.parseParameters(location.getQuery());
			
			assertEquals(2, params.size());
			assertEquals(ErrorCode.INVALID_REQUEST.getCode(), params.get("error"));
			assertEquals(ErrorCode.INVALID_REQUEST.getDescription(), params.get("error_description"));
			
			HTTPResponse httpResponse = r.toHTTPResponse();
			
			assertEquals(HTTPResponse.SC_FOUND, httpResponse.getStatusCode());
			assertEquals(location, httpResponse.getLocation());
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
	}
	
	
	public void testConstructorFull() {
	
		ResponseTypeSet rts = new ResponseTypeSet();
		rts.add(ResponseType.CODE);
	
		AuthorizationErrorResponse r = new AuthorizationErrorResponse(REDIRECT_URL, 
		                                                              ErrorCode.INVALID_REQUEST,
									      ERROR_PAGE_URL,
									      rts,
									      new State("123"));

		assertEquals(ErrorCode.INVALID_REQUEST, r.getErrorCode());
		assertEquals(ERROR_PAGE_URL, r.getErrorURI());
		assertNotNull(r.getResponseTypeSet());
		assertEquals(1, r.getResponseTypeSet().size());
		assertTrue(r.getResponseTypeSet().contains(ResponseType.CODE));
		assertEquals(new State("123"), r.getState());
		
		try {
			URL location = r.toURL();
			
			System.out.println(location.toString());
			
			assertNull(location.getRef());
			assertNotNull(location.getQuery());
			
			assertEquals(REDIRECT_URL.getProtocol(), location.getProtocol());
			assertEquals(REDIRECT_URL.getPort(), location.getPort());
			assertEquals(REDIRECT_URL.getHost(), location.getHost());
			assertEquals(REDIRECT_URL.getPath(), location.getPath());
			
			Map<String,String> params = URLUtils.parseParameters(location.getQuery());
			
			assertEquals(4, params.size());
			assertEquals(ErrorCode.INVALID_REQUEST.getCode(), params.get("error"));
			assertEquals(ErrorCode.INVALID_REQUEST.getDescription(), params.get("error_description"));
			assertEquals(ERROR_PAGE_URL.toString(), params.get("error_uri"));
			assertEquals("123", params.get("state"));
			
			HTTPResponse httpResponse = r.toHTTPResponse();
			
			assertEquals(HTTPResponse.SC_FOUND, httpResponse.getStatusCode());
			assertEquals(location, httpResponse.getLocation());
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
	}
	
	
	public void testConstructorForObservingLegalErrorCodes() {
	
		ResponseTypeSet rts = new ResponseTypeSet();
		rts.add(ResponseType.CODE);
		
		new AuthorizationErrorResponse(REDIRECT_URL, ErrorCode.INVALID_REQUEST, null, rts, null);
		new AuthorizationErrorResponse(REDIRECT_URL, ErrorCode.UNAUTHORIZED_CLIENT, null, rts, null);
		new AuthorizationErrorResponse(REDIRECT_URL, ErrorCode.ACCESS_DENIED, null, rts, null);
		new AuthorizationErrorResponse(REDIRECT_URL, ErrorCode.UNSUPPORTED_RESPONSE_TYPE, null, rts, null);
		new AuthorizationErrorResponse(REDIRECT_URL, ErrorCode.INVALID_SCOPE, null, rts, null);
		new AuthorizationErrorResponse(REDIRECT_URL, ErrorCode.SERVER_ERROR, null, rts, null);
		new AuthorizationErrorResponse(REDIRECT_URL, ErrorCode.TEMPORARILY_UNAVAILABLE, null, rts, null);
		new AuthorizationErrorResponse(REDIRECT_URL, ErrorCode.INVALID_REDIRECT_URI, null, rts, null);
		
		new AuthorizationErrorResponse(REDIRECT_URL, ErrorCode.INTERACTION_REQUIRED, null, rts, null);
		new AuthorizationErrorResponse(REDIRECT_URL, ErrorCode.LOGIN_REQUIRED, null, rts, null);
		new AuthorizationErrorResponse(REDIRECT_URL, ErrorCode.SESSION_SELECTION_REQUIRED, null, rts, null);
		new AuthorizationErrorResponse(REDIRECT_URL, ErrorCode.CONSENT_REQUIRED, null, rts, null);
		new AuthorizationErrorResponse(REDIRECT_URL, ErrorCode.INVALID_REQUEST_URI, null, rts, null);
		new AuthorizationErrorResponse(REDIRECT_URL, ErrorCode.INVALID_OPENID_REQUEST_OBJECT, null, rts, null);
		
		try {
			new AuthorizationErrorResponse(REDIRECT_URL, ErrorCode.INVALID_SCHEMA, null, rts, null);
			
			fail("Failed to raise exception");
			
		} catch (IllegalArgumentException e) {
		
			// ok
		}					      
	}
	
	
	public void testLegalErrorCodesGetter() {
	
		Set<ErrorCode> codes = AuthorizationErrorResponse.getLegalErrorCodes();
	
		assertTrue(codes.contains(ErrorCode.INVALID_REQUEST));
		assertTrue(codes.contains(ErrorCode.UNAUTHORIZED_CLIENT));
		assertTrue(codes.contains(ErrorCode.ACCESS_DENIED));
		assertTrue(codes.contains(ErrorCode.UNSUPPORTED_RESPONSE_TYPE));
		assertTrue(codes.contains(ErrorCode.INVALID_SCOPE));
		assertTrue(codes.contains(ErrorCode.SERVER_ERROR));
		assertTrue(codes.contains(ErrorCode.TEMPORARILY_UNAVAILABLE));
		assertTrue(codes.contains(ErrorCode.INVALID_REDIRECT_URI));

		assertTrue(codes.contains(ErrorCode.INTERACTION_REQUIRED));
		assertTrue(codes.contains(ErrorCode.LOGIN_REQUIRED));
		assertTrue(codes.contains(ErrorCode.SESSION_SELECTION_REQUIRED));
		assertTrue(codes.contains(ErrorCode.CONSENT_REQUIRED));
		assertTrue(codes.contains(ErrorCode.INVALID_REQUEST_URI));
		assertTrue(codes.contains(ErrorCode.INVALID_OPENID_REQUEST_OBJECT));
		
		assertEquals(14, codes.size());
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
		assertEquals(ErrorCode.INVALID_REQUEST, r.getErrorCode());
		assertEquals(ERROR_PAGE_URL, r.getErrorURI());
		assertEquals(new State("123"), r.getState());
		
		assertNull(r.getResponseTypeSet());
	}
	
	
	public void testParseExceptions()
		throws MalformedURLException {
	
		String s1 = "https://client.example.com/cb?error=invalid_request&error_description=Invalid+request&error_uri=http%3A%2F%2Fserver.example.com%2Ferror%2F123&state=123&abc=def";
		
		try {
			AuthorizationErrorResponse.parse(new URL(s1));
			fail("Failed to raise exception: Too many params");
			
		} catch (ParseException e) {
		
			System.out.println(e);
		}
		
		
		String s2 = "https://client.example.com/cb";
		
		try {
			AuthorizationErrorResponse.parse(new URL(s2));
			fail("Failed to raise exception: No params");
			
		} catch (ParseException e) {
		
			System.out.println(e);
		}
		
		
		String s3 = "https://client.example.com/cb?error=abc&error_description=Invalid+request&error_uri=http%3A%2F%2Fserver.example.com%2Ferror%2F123&state=123";
		
		try {
			AuthorizationErrorResponse.parse(new URL(s3));
			fail("Failed to raise exception: Invalid error code");
			
		} catch (ParseException e) {
		
			System.out.println(e);
		}
		
		
		String s4 = "https://client.example.com/cb?error=invalid_request&error_uri=example.html";
		
		try {
			AuthorizationErrorResponse.parse(new URL(s4));
			fail("Failed to raise exception: Invalid error URI");
			
		} catch (ParseException e) {
		
			System.out.println(e);
		}
	}
}
