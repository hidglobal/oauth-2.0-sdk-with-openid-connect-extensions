package com.nimbusds.openid.connect.messages;


import java.net.URL;


/**
 * Interface for OpenID Connect error response messages.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-05-11)
 */
public interface ErrorResponse extends Response {


	/**
	 * Gets the error code and description associated with the error 
	 * response.
	 *
	 * @return The error code.
	 */
	public ErrorCode getErrorCode();
	
	
	/**
	 * Returns an optional URI of a human-readable web page with information
	 * about the error.
	 *
	 * @return The error page URI, {@code null} if not specified.
	 */
	public URL getErrorURI();
}
