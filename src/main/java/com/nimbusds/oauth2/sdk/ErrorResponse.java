package com.nimbusds.oauth2.sdk;


/**
 * Response message indicating an error.
 *
 * @author Vladimir Dzhuvinov
 */
public interface ErrorResponse extends Response {


	/**
	 * Gets the error associated with the error response.
	 *
	 * @return The error, {@code null} if none.
	 */
	public ErrorObject getErrorObject();
}
