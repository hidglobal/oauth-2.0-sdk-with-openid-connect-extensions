package com.nimbusds.oauth2.sdk;


import java.net.URL;


/**
 * Response message indicating an error.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-30)
 */
public interface ErrorResponse extends Response {


	/**
	 * Gets the error associated with the error response.
	 *
	 * @return The error, {@code null} if none.
	 */
	public ErrorObject getErrorObject();
}
