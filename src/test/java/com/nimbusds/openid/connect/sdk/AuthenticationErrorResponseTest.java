package com.nimbusds.openid.connect.sdk;


import java.net.URI;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.State;


/**
 * Tests the authentication error response class.
 */
public class AuthenticationErrorResponseTest extends TestCase {


	public void testCodeErrorResponse()
		throws Exception {

		URI redirectURI = new URI("https://client.com/cb");
		ErrorObject error = OAuth2Error.ACCESS_DENIED;
		ResponseType responseType = new ResponseType("code");
		State state = new State("123");

		AuthenticationErrorResponse response = new AuthenticationErrorResponse(
			redirectURI, error, responseType, state);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertEquals(responseType, response.getResponseType());
		assertEquals(state, response.getState());

		URI responseURI = response.toURI();

		String[] parts = responseURI.toString().split("\\?");
		assertEquals(redirectURI.toString(), parts[0]);

		assertNotNull(responseURI.getQuery());
		assertNull(responseURI.getFragment());

		response = AuthenticationErrorResponse.parse(responseURI);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertNull(response.getResponseType());
		assertEquals(state, response.getState());
	}


	public void testIDTokenErrorResponse()
		throws Exception {

		URI redirectURI = new URI("https://client.com/cb");
		ErrorObject error = OAuth2Error.ACCESS_DENIED;
		ResponseType responseType = new ResponseType("id_token");
		State state = new State("123");

		AuthenticationErrorResponse response = new AuthenticationErrorResponse(
			redirectURI, error, responseType, state);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertEquals(responseType, response.getResponseType());
		assertEquals(state, response.getState());

		URI responseURI = response.toURI();

		String[] parts = responseURI.toString().split("#");
		assertEquals(redirectURI.toString(), parts[0]);

		assertNull(responseURI.getQuery());
		assertNotNull(responseURI.getFragment());

		response = AuthenticationErrorResponse.parse(responseURI);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertNull(response.getResponseType());
		assertEquals(state, response.getState());
	}
}
