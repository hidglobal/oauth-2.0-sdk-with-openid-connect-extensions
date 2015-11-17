package com.nimbusds.oauth2.sdk;


import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import junit.framework.TestCase;


/**
 * Tests the token introspection error class.
 */
public class TokenIntrospectionErrorResponseTest extends TestCase {
	

	public void testStdErrors() {

		assertTrue(TokenIntrospectionErrorResponse.getStandardErrors().contains(OAuth2Error.INVALID_REQUEST));
		assertTrue(TokenIntrospectionErrorResponse.getStandardErrors().contains(OAuth2Error.INVALID_CLIENT));

		assertTrue(TokenIntrospectionErrorResponse.getStandardErrors().contains(BearerTokenError.MISSING_TOKEN));
		assertTrue(TokenIntrospectionErrorResponse.getStandardErrors().contains(BearerTokenError.INVALID_REQUEST));
		assertTrue(TokenIntrospectionErrorResponse.getStandardErrors().contains(BearerTokenError.INVALID_TOKEN));
		assertTrue(TokenIntrospectionErrorResponse.getStandardErrors().contains(BearerTokenError.INSUFFICIENT_SCOPE));

		assertEquals(5, TokenIntrospectionErrorResponse.getStandardErrors().size());
	}


	public void testNoErrorObject() {

		TokenIntrospectionErrorResponse errorResponse = new TokenIntrospectionErrorResponse(null);
		assertFalse(errorResponse.indicatesSuccess());
		assertNull(errorResponse.getErrorObject());
		HTTPResponse httpResponse = errorResponse.toHTTPResponse();
		assertEquals(400, httpResponse.getStatusCode());
		assertNull(httpResponse.getContentType());
		assertNull(httpResponse.getContent());
	}


	public void testInvalidClientAuth()
		throws ParseException {

		TokenIntrospectionErrorResponse errorResponse = new TokenIntrospectionErrorResponse(OAuth2Error.INVALID_CLIENT);
		assertFalse(errorResponse.indicatesSuccess());
		assertEquals(OAuth2Error.INVALID_CLIENT, errorResponse.getErrorObject());

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();

		assertEquals(401, httpResponse.getStatusCode());
		assertTrue(CommonContentTypes.APPLICATION_JSON.match(httpResponse.getContentType()));
		assertTrue(OAuth2Error.INVALID_CLIENT.getCode().equals(ErrorObject.parse(httpResponse.getContentAsJSONObject()).getCode()));
		assertTrue(OAuth2Error.INVALID_CLIENT.getDescription().equals(ErrorObject.parse(httpResponse.getContentAsJSONObject()).getDescription()));

		errorResponse = TokenIntrospectionErrorResponse.parse(httpResponse);

		assertFalse(errorResponse.indicatesSuccess());
		assertEquals(OAuth2Error.INVALID_CLIENT, errorResponse.getErrorObject());
	}


	public void testInvalidClientAuthz()
		throws ParseException {

		TokenIntrospectionErrorResponse errorResponse = new TokenIntrospectionErrorResponse(BearerTokenError.INVALID_TOKEN);
		assertFalse(errorResponse.indicatesSuccess());
		assertEquals(BearerTokenError.INVALID_TOKEN, errorResponse.getErrorObject());

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();

		assertEquals(401, httpResponse.getStatusCode());
		assertEquals(BearerTokenError.INVALID_TOKEN.toWWWAuthenticateHeader(), httpResponse.getWWWAuthenticate());
		assertTrue(CommonContentTypes.APPLICATION_JSON.match(httpResponse.getContentType()));
		assertTrue(BearerTokenError.INVALID_TOKEN.getCode().equals(ErrorObject.parse(httpResponse.getContentAsJSONObject()).getCode()));
		assertTrue(BearerTokenError.INVALID_TOKEN.getDescription().equals(ErrorObject.parse(httpResponse.getContentAsJSONObject()).getDescription()));

		errorResponse = TokenIntrospectionErrorResponse.parse(httpResponse);

		assertFalse(errorResponse.indicatesSuccess());
		assertEquals(BearerTokenError.INVALID_TOKEN, errorResponse.getErrorObject());
	}
}
