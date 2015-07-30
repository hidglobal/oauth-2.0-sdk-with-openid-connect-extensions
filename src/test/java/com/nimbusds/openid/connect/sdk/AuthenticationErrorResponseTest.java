package com.nimbusds.openid.connect.sdk;


import java.net.URI;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Tests the authentication error response class.
 */
public class AuthenticationErrorResponseTest extends TestCase {


	public void testCodeErrorResponse()
		throws Exception {

		URI redirectURI = new URI("https://client.com/cb");
		ErrorObject error = OAuth2Error.ACCESS_DENIED;
		State state = new State("123");

		AuthenticationErrorResponse response = new AuthenticationErrorResponse(
			redirectURI, error, state, ResponseMode.QUERY);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertEquals(ResponseMode.QUERY, response.getResponseMode());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());
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
		assertEquals(state, response.getState());
		assertNull(response.getResponseMode());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());
	}


	public void testIDTokenErrorResponse()
		throws Exception {

		URI redirectURI = new URI("https://client.com/cb");
		ErrorObject error = OAuth2Error.ACCESS_DENIED;
		State state = new State("123");

		AuthenticationErrorResponse response = new AuthenticationErrorResponse(
			redirectURI, error, state, ResponseMode.FRAGMENT);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertEquals(ResponseMode.FRAGMENT, response.getResponseMode());
		assertEquals(ResponseMode.FRAGMENT, response.impliedResponseMode());
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
		assertEquals(state, response.getState());
		assertNull(response.getResponseMode());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());
	}


	public void testRedirectionURIWithQueryString()
		throws Exception {
		// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/140

		URI redirectURI = URI.create("https://example.com/myservice/?action=oidccallback");
		assertEquals("action=oidccallback", redirectURI.getQuery());

		State state = new State();

		ErrorObject error = OAuth2Error.ACCESS_DENIED;

		AuthenticationErrorResponse response = new AuthenticationErrorResponse(redirectURI, error, state, ResponseMode.QUERY);

		Map<String,String> params = response.toParameters();
		assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), params.get("error"));
		assertEquals(OAuth2Error.ACCESS_DENIED.getDescription(), params.get("error_description"));
		assertEquals(state.getValue(), params.get("state"));
		assertEquals(3, params.size());

		URI uri = response.toURI();

		params = URLUtils.parseParameters(uri.getQuery());
		assertEquals("oidccallback", params.get("action"));
		assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), params.get("error"));
		assertEquals(OAuth2Error.ACCESS_DENIED.getDescription(), params.get("error_description"));
		assertEquals(state.getValue(), params.get("state"));
		assertEquals(4, params.size());
	}
}
