package com.nimbusds.oauth2.sdk;


import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Tests the bearer access token error response class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-21)
 */
public class BearerAccessTokenErrorResponseTest extends TestCase {


	public void testStandardErrors() {

		Set<OAuth2Error> errors = BearerAccessTokenErrorResponse.getStandardErrors();

		assertTrue(errors.contains(OAuth2Error.INVALID_REQUEST));
		assertTrue(errors.contains(OAuth2Error.INVALID_TOKEN));
		assertTrue(errors.contains(OAuth2Error.INSUFFICIENT_SCOPE));

		assertEquals(3, errors.size());
	}


	public void testSerializeAndParseWWWAuthHeader()
		throws Exception {

		String realm = "example.com";

		BearerAccessTokenErrorResponse resp = 
			new BearerAccessTokenErrorResponse(realm, OAuth2Error.INVALID_TOKEN);

		assertEquals(realm, resp.getRealm());
		assertEquals(OAuth2Error.INVALID_TOKEN, resp.getError());

		String wwwAuth = resp.toWWWAuthenticateHeader();

		System.out.println("WWW-Authenticate: " + wwwAuth);

		resp = BearerAccessTokenErrorResponse.parse(wwwAuth);

		assertEquals(realm, resp.getRealm());
		assertEquals(OAuth2Error.INVALID_TOKEN, resp.getError());
	}


	public void testSerializeAndParseHTTPResponse()
		throws Exception {

		String realm = "example.com";

		BearerAccessTokenErrorResponse resp = 
			new BearerAccessTokenErrorResponse(realm, OAuth2Error.INVALID_TOKEN);

		assertEquals(realm, resp.getRealm());
		assertEquals(OAuth2Error.INVALID_TOKEN, resp.getError());

		HTTPResponse httpResponse = resp.toHTTPResponse();
		assertEquals(401, httpResponse.getStatusCode());

		resp = BearerAccessTokenErrorResponse.parse(httpResponse);

		assertEquals(realm, resp.getRealm());
		assertEquals(OAuth2Error.INVALID_TOKEN, resp.getError());
	}


	public void testNullRealm() {

		BearerAccessTokenErrorResponse resp = 
			new BearerAccessTokenErrorResponse(null, OAuth2Error.INVALID_TOKEN);

		assertNull(resp.getRealm());
	}


	public void testNullError() {

		BearerAccessTokenErrorResponse resp = 
			new BearerAccessTokenErrorResponse("example.con", null);

		assertNull(resp.getError());
	}
}
