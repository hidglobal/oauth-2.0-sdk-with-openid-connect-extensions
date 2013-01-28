package com.nimbusds.oauth2.sdk;


import java.net.URL;


/**
 * Response message indicating an error.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-28)
 */
public interface ErrorResponse extends Response {


	/**
	 * Gets the OAuth 2.0 error associated with the error response.
	 *
	 * @return The OAuth 2.0 error, {@code null} if none.
	 */
	public OAuth2Error getOAuth2Error();
}
