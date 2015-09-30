package com.nimbusds.oauth2.sdk.auth.verifier;


import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;


/**
 * Failed client authentication exception. Typical causes are unknown client,
 * no client authentication included, invalid credentials or unsupported
 * authentication method.
 */
public class InvalidClientException extends Exception {


	/**
	 * Creates a new invalid client exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 */
	public InvalidClientException(final String message) {

		super(message);
	}


	/**
	 * Creates a new invalid client exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public InvalidClientException(final String message, final Throwable cause) {

		super(message, cause);
	}


	/**
	 * Returns a basic OAuth 2.0 {@code invalid_client} error.
	 *
	 * @return An {@link OAuth2Error#INVALID_CLIENT invalid_client} error.
	 */
	public ErrorObject toErrorObject() {

		return OAuth2Error.INVALID_CLIENT;
	}


	/**
	 * Returns an OAuth 2.0 {@code invalid_client} error with the exception
	 * message appended to the description.
	 *
	 * @return An {@link OAuth2Error#INVALID_CLIENT invalid_client} error
	 *         with additional description.
	 */
	public ErrorObject toErrorObjectWithDescription() {

		ErrorObject basicError = toErrorObject();

		if (getMessage() != null) {
			return basicError.appendDescription(": " + getMessage());
		}

		return basicError;
	}
}
