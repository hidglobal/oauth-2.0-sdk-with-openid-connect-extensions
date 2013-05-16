package com.nimbusds.oauth2.sdk.token;


import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Tests the bearer token error class.
 *
 * @author Vladimir Dzhuvinov
 */
public class BearerTokenErrorTest extends TestCase {


	public void testConstantCodes() {

		assertNull(BearerTokenError.MISSING_TOKEN.getCode());
		assertEquals("invalid_request", BearerTokenError.INVALID_REQUEST.getCode());
		assertEquals("invalid_token", BearerTokenError.INVALID_TOKEN.getCode());
		assertEquals("insufficient_scope", BearerTokenError.INSUFFICIENT_SCOPE.getCode());
	}


	public void testSerializeAndParseWWWAuthHeader()
		throws Exception {

		BearerTokenError error = BearerTokenError.INVALID_TOKEN.setRealm("example.com");

		assertEquals("example.com", error.getRealm());
		assertEquals("invalid_token", error.getCode());

		String wwwAuth = error.toWWWAuthenticateHeader();

		System.out.println("WWW-Authenticate: " + wwwAuth);

		error = BearerTokenError.parse(wwwAuth);

		assertEquals("example.com", error.getRealm());
		assertEquals("invalid_token", error.getCode());
	}


	public void testNullRealm() {

		BearerTokenError error = BearerTokenError.INVALID_REQUEST.setRealm(null);

		assertNull(error.getRealm());
	}


	public void testNoErrorCode()
		throws Exception {

		String wwwAuth = "Bearer realm=\"example.com\"";

		BearerTokenError error = BearerTokenError.parse(wwwAuth);

		assertEquals(error, BearerTokenError.MISSING_TOKEN);

		assertEquals("example.com", error.getRealm());
		assertNull(error.getCode());
	}
}
