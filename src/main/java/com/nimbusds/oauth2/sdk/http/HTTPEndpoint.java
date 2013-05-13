package com.nimbusds.oauth2.sdk.http;


/**
 * HTTP endpoint.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-02-27)
 */
public interface HTTPEndpoint {


	/**
	 * Processes an HTTP request.
	 *
	 * @param httpRequest The HTTP request to process. Must not be
	 *                    {@code null}.
	 *
	 * @return The HTTP response.
	 */
	public HTTPResponse process(final HTTPRequest httpRequest);
}