package com.nimbusds.oauth2.sdk;


import junit.framework.TestCase;


/**
 * Tests the OAuth 2.0 error constants.
 *
 * @author Vladimir Dzhuvinov
 */
public class OAuth2ErrorTest extends TestCase {


	public void testHTTPStatusCodes() {

		assertEquals(403, OAuth2Error.ACCESS_DENIED.getHTTPStatusCode());
		assertEquals(401, OAuth2Error.INVALID_CLIENT.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.INVALID_GRANT.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.INVALID_REQUEST.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.INVALID_SCOPE.getHTTPStatusCode());
		assertEquals(500, OAuth2Error.SERVER_ERROR.getHTTPStatusCode());
		assertEquals(503, OAuth2Error.TEMPORARILY_UNAVAILABLE.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.UNAUTHORIZED_CLIENT.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.UNSUPPORTED_GRANT_TYPE.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE.getHTTPStatusCode());
	}
}
