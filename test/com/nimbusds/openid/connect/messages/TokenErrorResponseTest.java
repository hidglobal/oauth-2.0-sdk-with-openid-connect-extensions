package com.nimbusds.openid.connect.messages;


import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.CommonContentTypes;
import com.nimbusds.openid.connect.http.HTTPResponse;

import com.nimbusds.openid.connect.util.JSONObjectUtils;
import com.nimbusds.openid.connect.util.URLUtils;


/**
 * Tests token error response serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.2 (2012-05-03)
 */
public class TokenErrorResponseTest extends TestCase {
	
	
	private static URL ERROR_PAGE_URL = null;
	
	
	public void setUp()
		throws MalformedURLException {
		
		ERROR_PAGE_URL = new URL("http://server.example.com/error/123");
	}
	
	
	public void testConstructorAndParserMinimal() {
	
		TokenErrorResponse r = new TokenErrorResponse(ErrorCode.INVALID_REQUEST, null);
		
		assertEquals(ErrorCode.INVALID_REQUEST, r.getErrorCode());
		assertNull(r.getErrorURI());
		
		HTTPResponse httpResponse = null;
		
		try {
			httpResponse = r.toHTTPResponse();
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(HTTPResponse.SC_BAD_REQUEST, httpResponse.getStatusCode());
		assertEquals(CommonContentTypes.APPLICATION_JSON, httpResponse.getContentType());
		assertEquals("no-store", httpResponse.getCacheControl());
		assertEquals("no-cache", httpResponse.getPragma());
		
		
		JSONObject jsonObject = null;
		
		try {
			jsonObject = JSONObjectUtils.parseJSONObject(httpResponse.getContent());	
		
		} catch (ParseException e) {
			
			fail(e.getMessage());
		}

		assertEquals(ErrorCode.INVALID_REQUEST.getCode(), (String)jsonObject.get("error"));
		assertEquals(ErrorCode.INVALID_REQUEST.getDescription(), (String)jsonObject.get("error_description"));
		assertEquals(2, jsonObject.size());
		
		
		try {
			r = TokenErrorResponse.parse(httpResponse);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(ErrorCode.INVALID_REQUEST, r.getErrorCode());
		assertNull(r.getErrorURI());
	}
	
	
	public void testConstructorAndParserFull() {
	
		TokenErrorResponse r = new TokenErrorResponse(ErrorCode.INVALID_REQUEST, ERROR_PAGE_URL);
		
		assertEquals(ErrorCode.INVALID_REQUEST, r.getErrorCode());
		assertEquals(ERROR_PAGE_URL, r.getErrorURI());
		
		HTTPResponse httpResponse = null;
		
		try {
			httpResponse = r.toHTTPResponse();
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(HTTPResponse.SC_BAD_REQUEST, httpResponse.getStatusCode());
		assertEquals(CommonContentTypes.APPLICATION_JSON, httpResponse.getContentType());
		assertEquals("no-store", httpResponse.getCacheControl());
		assertEquals("no-cache", httpResponse.getPragma());
		
		
		JSONObject jsonObject = null;
		
		try {
			jsonObject = JSONObjectUtils.parseJSONObject(httpResponse.getContent());	
		
		} catch (ParseException e) {
			
			fail(e.getMessage());
		}

		assertEquals(ErrorCode.INVALID_REQUEST.getCode(), (String)jsonObject.get("error"));
		assertEquals(ErrorCode.INVALID_REQUEST.getDescription(), (String)jsonObject.get("error_description"));
		assertEquals(ERROR_PAGE_URL.toString(), (String)jsonObject.get("error_uri"));
		assertEquals(3, jsonObject.size());
		
		
		try {
			r = TokenErrorResponse.parse(httpResponse);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(ErrorCode.INVALID_REQUEST, r.getErrorCode());
		assertEquals(ERROR_PAGE_URL, r.getErrorURI());
	}
	
	
	public void testConstructorForObservingLegalErrorCodes() {
	
		new TokenErrorResponse(ErrorCode.INVALID_REQUEST, null);
		new TokenErrorResponse(ErrorCode.INVALID_CLIENT, null);
		new TokenErrorResponse(ErrorCode.INVALID_GRANT, null);
		new TokenErrorResponse(ErrorCode.UNAUTHORIZED_CLIENT, null);
		new TokenErrorResponse(ErrorCode.UNSUPPORTED_GRANT_TYPE, null);
		new TokenErrorResponse(ErrorCode.INVALID_SCOPE, null);
		
		try {
			new TokenErrorResponse(ErrorCode.INVALID_SCHEMA, null);
			
			fail("Failed to raise exception");
			
		} catch (IllegalArgumentException e) {
		
			// ok
		}		      
	}
	
	
	public void testLegalErrorCodesGetter() {
	
		Set<ErrorCode> codes = TokenErrorResponse.getLegalErrorCodes();
	
		assertTrue(codes.contains(ErrorCode.INVALID_REQUEST));
		assertTrue(codes.contains(ErrorCode.INVALID_CLIENT));
		assertTrue(codes.contains(ErrorCode.INVALID_GRANT));
		assertTrue(codes.contains(ErrorCode.UNAUTHORIZED_CLIENT));
		assertTrue(codes.contains(ErrorCode.UNSUPPORTED_GRANT_TYPE));
		assertTrue(codes.contains(ErrorCode.INVALID_SCOPE));
		
		assertEquals(6, codes.size());
	}
}
