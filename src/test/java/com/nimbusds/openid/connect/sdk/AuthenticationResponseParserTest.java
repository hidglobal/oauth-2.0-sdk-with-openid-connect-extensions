package com.nimbusds.openid.connect.sdk;


import java.net.URI;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
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

		AuthenticationSuccessResponse successResponse = new AuthenticationSuccessResponse(redirectURI, code, null, null, state);

		HTTPResponse httpResponse = successResponse.toHTTPResponse();

		AuthenticationResponse response = AuthenticationResponseParser.parse(httpResponse);

		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(state, response.getState());

		successResponse = (AuthenticationSuccessResponse)response;
		assertEquals(code, successResponse.getAuthorizationCode());
	}


	public void testParseError()
		throws Exception {

		URI redirectURI = new URI("https://example.com/in");
		ResponseType rt = new ResponseType(ResponseType.Value.CODE);
		State state = new State("xyz");

		AuthenticationErrorResponse errorResponse = new AuthenticationErrorResponse(redirectURI, OAuth2Error.ACCESS_DENIED, rt, state);

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();

		AuthenticationResponse response = AuthenticationResponseParser.parse(httpResponse);

		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(state, response.getState());

		errorResponse = (AuthenticationErrorResponse)response;
		assertEquals(OAuth2Error.ACCESS_DENIED, errorResponse.getErrorObject());
	}
}
