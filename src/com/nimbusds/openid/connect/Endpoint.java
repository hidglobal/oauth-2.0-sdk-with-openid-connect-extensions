package com.nimbusds.openid.connect;


import com.nimbusds.openid.connect.http.HTTPRequest;
import com.nimbusds.openid.connect.http.HTTPResponse;


/**
 * Authorisation server endpoint.
 *
 * <p>Parses incoming {@link HTTPRequest}s into OpenID Connect {@link Request} 
 * objects which are then passed to a dedicated {@link RequestHandler} to 
 * perform the actual back-end processing (e.g. by making a database query).
 *
 * <p>If the {@link HTTPRequest} doesn't parse to a valid OpenID Connect 
 * {@link Request} or the request is found to be otherwise invalid, the endpoint
 * may choose to return a {@link HTTPResponse} indicating an 
 * {@link ErrorCode error} without the {@link RequestHandler} being called.
 *
 * <p>To do: Add event handler setter for logging and monitoring purposes.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-03-15)
 */
public interface Endpoint {


	/**
	 * Sets a handler for OpenID Connect {@link Request}s received at the 
	 * endpoint.
	 *
	 * @param handler The handler.
	 */
	public void setRequestHandler(final RequestHandler handler);
	
	
	/**
	 * Gets the handler for OpenID Connect {@link Request}s received at the
	 * endpoint.
	 *
	 * @return The handler.
	 */
	public RequestHandler getRequestHandler();
	
	
	/**
	 * Processes an HTTP request at the endpoint.
	 *
	 * @param httpRequest The HTTP request to process.
	 *
	 * @return The resulting HTTP response.
	 */
	public HTTPResponse process(final HTTPRequest httpRequest);
}
