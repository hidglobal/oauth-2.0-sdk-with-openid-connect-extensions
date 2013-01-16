package com.nimbusds.oauth2.sdk;


import java.net.URL;


/**
 * OAuth 2.0 error response message.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-16)
 */
public interface OAuth2ErrorResponse extends OAuth2Response {


	/**
	 * Gets the OAuth 2.0 error associated with the error response.
	 *
	 * @return The error.
	 */
	public OAuth2Error getError();
}
