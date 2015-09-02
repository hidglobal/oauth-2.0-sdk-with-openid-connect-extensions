package com.nimbusds.oauth2.sdk;


import java.net.URI;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.id.State;


/**
 * Tests the authorisation response class.
 */
public class AuthorizationResponseTest extends TestCase {


	// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/147/authorizationrequestparse-final-uri-uri
	public void testParseWithEncodedEqualsChar()
		throws Exception {

		URI redirectURI = URI.create("https://example.com/in");

		AuthorizationCode code = new AuthorizationCode("===code===");
		State state = new State("===state===");

		AuthorizationResponse response = new AuthorizationSuccessResponse(redirectURI, code, null, state, ResponseMode.QUERY);

		URI uri = response.toURI();

		response = AuthorizationResponse.parse(uri);

		assertEquals(state, response.getState());

		AuthorizationSuccessResponse successResponse = (AuthorizationSuccessResponse)response;

		assertEquals(code, successResponse.getAuthorizationCode());
		assertNull(successResponse.getAccessToken());
	}
}
