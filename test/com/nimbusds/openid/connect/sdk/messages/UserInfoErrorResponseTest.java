package com.nimbusds.openid.connect.sdk.messages;


import java.net.MalformedURLException;
import java.net.URL;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.openid.connect.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.SerializeException;

import com.nimbusds.openid.connect.sdk.http.HTTPResponse;


/**
 * Tests UserInfo error response serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-22)
 */
public class UserInfoErrorResponseTest extends TestCase {
	
	
	private static String REALM = "example.com";
	
	
	private static URL REDIRECT_URL = null;
	
	
	private static URL ERROR_PAGE_URL = null;
	
	
	public void setUp()
		throws MalformedURLException {
		
		REDIRECT_URL = new URL("https://client.example.com/cb");
		
		ERROR_PAGE_URL = new URL("http://server.example.com/error/123");
	}

	public void testConstuctorMinimal() {
	
		UserInfoErrorResponse r = new UserInfoErrorResponse(null, ErrorCode.INVALID_REQUEST, null);
		
		assertNull(r.getRealm());
		assertEquals(ErrorCode.INVALID_REQUEST, r.getErrorCode());
		assertNull(r.getErrorURI());
		
		HTTPResponse httpResponse = null;
		
		try {
			httpResponse = r.toHTTPResponse();
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(HTTPResponse.SC_BAD_REQUEST, httpResponse.getStatusCode());
		
		String wwwAuth = httpResponse.getWWWAuthenticate();
		
		assertNotNull(wwwAuth);
		assertEquals("Bearer error=\"invalid_request\", error_description=\"Invalid request\"", wwwAuth);
		
		try {
			r = UserInfoErrorResponse.parse(httpResponse);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertNull(r.getRealm());
		assertEquals(ErrorCode.INVALID_REQUEST, r.getErrorCode());
		assertNull(r.getErrorURI());
	}
	
	
	public void testConstuctorFull() {
	
		UserInfoErrorResponse r = new UserInfoErrorResponse(REALM, ErrorCode.INVALID_REQUEST, ERROR_PAGE_URL);
		
		assertEquals(REALM, r.getRealm());
		assertEquals(ErrorCode.INVALID_REQUEST, r.getErrorCode());
		assertEquals(ERROR_PAGE_URL, r.getErrorURI());
		
		HTTPResponse httpResponse = null;
		
		try {
			httpResponse = r.toHTTPResponse();
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(HTTPResponse.SC_BAD_REQUEST, httpResponse.getStatusCode());
		
		String wwwAuth = httpResponse.getWWWAuthenticate();
		
		assertNotNull(wwwAuth);
		assertEquals("Bearer realm=\"example.com\", error=\"invalid_request\", error_description=\"Invalid request\", error_uri=\"http://server.example.com/error/123\"", wwwAuth);
		
		
		try {
			r = UserInfoErrorResponse.parse(httpResponse);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(REALM, r.getRealm());
		assertEquals(ErrorCode.INVALID_REQUEST, r.getErrorCode());
		assertEquals(ERROR_PAGE_URL, r.getErrorURI());
	}
	
	
	public void testConstructorForObservingLegalErrorCodes() {
	
		new UserInfoErrorResponse(null, ErrorCode.INVALID_REQUEST, null);
		new UserInfoErrorResponse(null, ErrorCode.INVALID_TOKEN, null);
		new UserInfoErrorResponse(null, ErrorCode.INSUFFICIENT_SCOPE, null);
		new UserInfoErrorResponse(null, ErrorCode.INVALID_SCHEMA, null);
		
		try {
			new UserInfoErrorResponse(null, ErrorCode.ACCESS_DENIED, null);
			
			fail("Failed to raise exception");
			
		} catch (IllegalArgumentException e) {
		
			// ok
		}		      
	}
	
	
	public void testLegalErrorCodesGetter() {
	
		Set<ErrorCode> codes = UserInfoErrorResponse.getLegalErrorCodes();
	
		assertTrue(codes.contains(ErrorCode.INVALID_REQUEST));
		assertTrue(codes.contains(ErrorCode.INVALID_TOKEN));
		assertTrue(codes.contains(ErrorCode.INSUFFICIENT_SCOPE));
		assertTrue(codes.contains(ErrorCode.INVALID_SCHEMA));
		
		assertEquals(4, codes.size());
	}
}
