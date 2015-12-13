package com.nimbusds.oauth2.sdk.assertions.saml2;


/**
 * Bad SAML 2.0 assertion exception.
 */
public class BadSAML2AssertionException extends Exception {
	

	/**
	 * Creates a new bad SAML 2.0 assertion exception.
	 *
	 * @param message The exception message.
	 */
	public BadSAML2AssertionException(final String message) {

		super(message);
	}


	/**
	 * Creates a new bad SAML 2.0 assertion exception.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public BadSAML2AssertionException(final String message, final Throwable cause) {

		super(message, cause);
	}
}
