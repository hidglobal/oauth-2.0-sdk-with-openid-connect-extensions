package com.nimbusds.oauth2.sdk.auth;


import java.net.URL;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;


/**
 * Tests the base client authentication class.
 */
public class ClientAuthenticationTest extends TestCase {


	// See issue 141
	public void testParseClientSecretPostNullSecret()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://googleapis.com/oauth2/v3/token"));
		httpRequest.setContentType("application/x-www-form-urlencoded");
		httpRequest.setQuery("code=4%2FiLoSjco7cxQJSnXBxaxaKCFGG0Au6Rm4H0ZrFV2-5jg&redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground&client_id=407408718192.apps.googleusercontent.com&client_secret=&scope=&grant_type=authorization_code");

		ClientAuthentication auth = ClientAuthentication.parse(httpRequest);
		assertNull(auth);
	}


	public void testParseClientSecretJWTNull()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://googleapis.com/oauth2/v3/token"));
		httpRequest.setContentType("application/x-www-form-urlencoded");
		httpRequest.setQuery("code=4%2FiLoSjco7cxQJSnXBxaxaKCFGG0Au6Rm4H0ZrFV2-5jg&redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground&client_assertion_type=&client_assertion=&scope=&grant_type=authorization_code");

		ClientAuthentication auth = ClientAuthentication.parse(httpRequest);
		assertNull(auth);
	}
}
