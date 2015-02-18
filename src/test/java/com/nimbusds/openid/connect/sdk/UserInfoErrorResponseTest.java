package com.nimbusds.openid.connect.sdk;


import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;


/**
 * Tests the UserInfo error response class.
 */
public class UserInfoErrorResponseTest extends TestCase {


	public void testStandardErrors() {

		assertTrue(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.INVALID_REQUEST));
		assertTrue(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.MISSING_TOKEN));
		assertTrue(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.INVALID_TOKEN));
		assertTrue(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.INSUFFICIENT_SCOPE));
		assertEquals(4, UserInfoErrorResponse.getStandardErrors().size());
	}


	public void testConstructAndParse()
		throws Exception {

		UserInfoErrorResponse errorResponse = new UserInfoErrorResponse(BearerTokenError.INVALID_TOKEN);

		assertFalse(errorResponse.indicatesSuccess());

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();

		assertEquals(401, httpResponse.getStatusCode());

		assertEquals("Bearer error=\"invalid_token\", error_description=\"Invalid access token\"", httpResponse.getWWWAuthenticate());

		errorResponse = UserInfoErrorResponse.parse(httpResponse);

		assertFalse(errorResponse.indicatesSuccess());

		assertEquals(BearerTokenError.INVALID_TOKEN, errorResponse.getErrorObject());
	}
}
