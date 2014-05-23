package com.nimbusds.oauth2.sdk.client;


import junit.framework.TestCase;


/**
 * Tests the registration error constants.
 */
public class RegistrationErrorTest extends TestCase {


	public void testConstants() {

		// http://tools.ietf.org/html/draft-ietf-oauth-dyn-reg-17#section-4.2

		assertEquals("invalid_redirect_uri", RegistrationError.INVALID_REDIRECT_URI.getCode());
		assertEquals("invalid_client_metadata", RegistrationError.INVALID_CLIENT_METADATA.getCode());
		assertEquals("invalid_software_statement", RegistrationError.INVALID_SOFTWARE_STATEMENT.getCode());
		assertEquals("unapproved_software_statement", RegistrationError.UNAPPROVED_SOFTWARE_STATEMENT.getCode());
	}
}
