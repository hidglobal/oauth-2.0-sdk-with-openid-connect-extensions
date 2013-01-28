package com.nimbusds.oauth2.sdk;


import com.nimbusds.oauth2.sdk.http.HTTPRequest;


/**
 * Request message, serialises to an HTTP request.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-16)
 */
public interface Request extends Message {


	/**
	 * Returns the matching HTTP request.
	 *
	 * @return The HTTP request.
	 *
	 * @throws SerializeException If the request message couldn't be
	 *                            serialised to an HTTP request.
	 */
	public HTTPRequest toHTTPRequest() 
		throws SerializeException;
}


