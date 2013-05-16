package com.nimbusds.oauth2.sdk;


import java.net.URL;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;


/**
 * Request message, serialises to an HTTP request.
 *
 * @author Vladimir Dzhuvinov
 */
public interface Request extends Message {


	/**
	 * Returns the matching HTTP request.
	 *
	 * @param url The URL of the HTTP endpoint for which the request is
	 *            intended. Must not be {@code null}.
	 *
	 * @return The HTTP request.
	 *
	 * @throws SerializeException If the request message couldn't be
	 *                            serialised to an HTTP request.
	 */
	public HTTPRequest toHTTPRequest(final URL url) 
		throws SerializeException;
}


