package com.nimbusds.oauth2.sdk.auth.verifier;


import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;


/**
 * Bad client exception.
 */
public class InvalidClientException extends Exception {


	public InvalidClientException(final String message) {

		super(message);
	}


	public ErrorObject toAuth2Error() {

		return OAuth2Error.INVALID_CLIENT;
	}
}
