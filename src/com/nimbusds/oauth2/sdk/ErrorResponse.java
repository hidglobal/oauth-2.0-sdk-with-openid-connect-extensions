package com.nimbusds.oauth2.sdk;


import java.net.URL;


/**
 * Interface for an OAuth 2.0 error response message.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-15)
 */
public interface ErrorResponse extends Response {


	/**
	 * Gets the OAuth 2.0 error associated with the error response.
	 *
	 * @return The error.
	 */
	public OAuth2Error getError();
}
