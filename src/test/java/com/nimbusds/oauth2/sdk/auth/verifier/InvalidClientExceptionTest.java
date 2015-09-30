package com.nimbusds.oauth2.sdk.auth.verifier;


import junit.framework.TestCase;

import com.nimbusds.jwt.proc.BadJWTException;

import com.nimbusds.oauth2.sdk.OAuth2Error;


/**
 * Tests the invalid client exception.
 */
public class InvalidClientExceptionTest extends TestCase {


	public void testMessage() {

		InvalidClientException e = new InvalidClientException("message");

		assertEquals("message", e.getMessage());
		assertNull(e.getCause());

		assertEquals(OAuth2Error.INVALID_CLIENT, e.toErrorObject());
		assertEquals(OAuth2Error.INVALID_CLIENT.getDescription() + ": message", e.toErrorObjectWithDescription().getDescription());
	}


	public void testMessageAndCause() {

		BadJWTException cause = new BadJWTException("Bad signature");
		InvalidClientException e = new InvalidClientException("message", cause);

		assertEquals("message", e.getMessage());
		assertEquals(cause, e.getCause());

		assertEquals(OAuth2Error.INVALID_CLIENT, e.toErrorObject());
		assertEquals(OAuth2Error.INVALID_CLIENT.getDescription() + ": message", e.toErrorObjectWithDescription().getDescription());
	}
}
