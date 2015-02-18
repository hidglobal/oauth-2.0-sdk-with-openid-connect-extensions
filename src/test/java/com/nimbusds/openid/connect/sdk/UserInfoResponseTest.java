package com.nimbusds.openid.connect.sdk;


import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;


/**
 * UserInfo response test.
 */
public class UserInfoResponseTest extends TestCase {


	public void testParseSuccess()
		throws Exception {

		UserInfoSuccessResponse successResponse = new UserInfoSuccessResponse(new UserInfo(new Subject("alice")));

		HTTPResponse httpResponse = successResponse.toHTTPResponse();

		UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponse);

		successResponse = (UserInfoSuccessResponse)userInfoResponse;

		assertEquals(new Subject("alice"), successResponse.getUserInfo().getSubject());
	}


	public void testParseBearerTokenError()
		throws Exception {

		UserInfoErrorResponse errorResponse = new UserInfoErrorResponse(BearerTokenError.INVALID_TOKEN);

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();

		UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponse);

		errorResponse = (UserInfoErrorResponse)userInfoResponse;

		assertEquals(BearerTokenError.INVALID_TOKEN, errorResponse.getErrorObject());
	}
}
