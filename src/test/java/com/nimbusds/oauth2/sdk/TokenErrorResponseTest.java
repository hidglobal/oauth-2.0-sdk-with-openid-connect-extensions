package com.nimbusds.oauth2.sdk;


import java.net.MalformedURLException;
import java.net.URL;
import java.util.Set;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Tests token error response serialisation and parsing.
 */
public class TokenErrorResponseTest extends TestCase {
	
	
	private static URL ERROR_PAGE_URL = null;
	
	
	public void setUp()
		throws MalformedURLException {
		
		ERROR_PAGE_URL = new URL("http://server.example.com/error/123");
	}


	public void testStandardErrors() {
	
		Set<ErrorObject> errors = TokenErrorResponse.getStandardErrors();
	
		assertTrue(errors.contains(OAuth2Error.INVALID_REQUEST));
		assertTrue(errors.contains(OAuth2Error.INVALID_CLIENT));
		assertTrue(errors.contains(OAuth2Error.INVALID_GRANT));
		assertTrue(errors.contains(OAuth2Error.UNAUTHORIZED_CLIENT));
		assertTrue(errors.contains(OAuth2Error.UNSUPPORTED_GRANT_TYPE));
		assertTrue(errors.contains(OAuth2Error.INVALID_SCOPE));
		
		assertEquals(6, errors.size());
	}
	
	
	public void testSerializeAndParse()
		throws Exception {
	
		ErrorObject err = OAuth2Error.INVALID_REQUEST.setURI(ERROR_PAGE_URL);

		TokenErrorResponse r = new TokenErrorResponse(err);
		
		assertEquals(OAuth2Error.INVALID_REQUEST, r.getErrorObject());
		

		HTTPResponse httpResponse = r.toHTTPResponse();
		
		assertEquals(HTTPResponse.SC_BAD_REQUEST, httpResponse.getStatusCode());
		assertEquals(CommonContentTypes.APPLICATION_JSON, httpResponse.getContentType());
		assertEquals("no-store", httpResponse.getCacheControl());
		assertEquals("no-cache", httpResponse.getPragma());
		
		
		JSONObject jsonObject = JSONObjectUtils.parseJSONObject(httpResponse.getContent());	

		assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), (String)jsonObject.get("error"));
		assertEquals(OAuth2Error.INVALID_REQUEST.getDescription(), (String)jsonObject.get("error_description"));
		assertEquals(ERROR_PAGE_URL.toString(), (String)jsonObject.get("error_uri"));
		assertEquals(3, jsonObject.size());
		
		
		r = TokenErrorResponse.parse(httpResponse);
		
		assertEquals(OAuth2Error.INVALID_REQUEST, r.getErrorObject());
	}


	public void testParseEmpty()
		throws Exception {

		HTTPResponse httpResponse = new HTTPResponse(404);

		TokenErrorResponse errorResponse = TokenErrorResponse.parse(httpResponse);

		assertNull(errorResponse.getErrorObject());
	}


	public void testParseInvalidClient()
		throws Exception {

		HTTPResponse httpResponse = new HTTPResponse(401);
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpResponse.setContent("{\"error\":\"invalid_client\", \"error_description\":\"Client authentication failed\"}");

		TokenErrorResponse errorResponse = TokenErrorResponse.parse(httpResponse);

		assertEquals(OAuth2Error.INVALID_CLIENT.getCode(), errorResponse.getErrorObject().getCode());
		assertEquals("Client authentication failed", errorResponse.getErrorObject().getDescription());
	}


	public void testTokenErrorWithoutObject()
		throws Exception {

		TokenErrorResponse errorResponse = new TokenErrorResponse();
		assertNull(errorResponse.getErrorObject());
		assertTrue(errorResponse.toJSONObject().isEmpty());

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();
		assertEquals(400, httpResponse.getStatusCode());
		assertNull(httpResponse.getContentType());
		assertNull(httpResponse.getContent());

		errorResponse = TokenErrorResponse.parse(httpResponse);
		assertNull(errorResponse.getErrorObject());
		assertTrue(errorResponse.toJSONObject().isEmpty());
	}
}
