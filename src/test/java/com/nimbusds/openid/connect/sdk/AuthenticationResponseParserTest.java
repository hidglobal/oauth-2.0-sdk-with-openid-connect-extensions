package com.nimbusds.openid.connect.sdk;


import java.net.URI;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.State;


/**
 * Tests the OpenID Connect authentication response parser.
 */
public class AuthenticationResponseParserTest extends TestCase {


	public void testParseSuccess()
		throws Exception {

		URI redirectURI = new URI("https://example.com/in");
		AuthorizationCode code = new AuthorizationCode("123");
		State state = new State("xyz");

		AuthenticationSuccessResponse successResponse = new AuthenticationSuccessResponse(
			redirectURI,
			code,
			null,
			null,
			state,
			null,
			null);

		HTTPResponse httpResponse = successResponse.toHTTPResponse();

		AuthenticationResponse response = AuthenticationResponseParser.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(state, response.getState());

		successResponse = (AuthenticationSuccessResponse)response;
		assertEquals(code, successResponse.getAuthorizationCode());
	}


	public void testParseError()
		throws Exception {

		URI redirectURI = new URI("https://example.com/in");
		State state = new State("xyz");

		AuthenticationErrorResponse errorResponse = new AuthenticationErrorResponse(
			redirectURI,
			OAuth2Error.ACCESS_DENIED,
			state,
			ResponseMode.QUERY);

		assertFalse(errorResponse.indicatesSuccess());

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();

		AuthenticationResponse response = AuthenticationResponseParser.parse(httpResponse);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(state, response.getState());

		errorResponse = (AuthenticationErrorResponse)response;
		assertEquals(OAuth2Error.ACCESS_DENIED, errorResponse.getErrorObject());
	}


	// see https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/162/authenticationresponseparser-does-not
	public void testParseAbsoluteURI()
		throws Exception {

		URI redirectURI = URI.create("http:///?code=Qcb0Orv1&state=af0ifjsldkj");

		AuthenticationResponse response = AuthenticationResponseParser.parse(redirectURI);

		AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse)response;

		assertEquals("Qcb0Orv1", successResponse.getAuthorizationCode().getValue());
		assertEquals("af0ifjsldkj", successResponse.getState().getValue());
	}
}
