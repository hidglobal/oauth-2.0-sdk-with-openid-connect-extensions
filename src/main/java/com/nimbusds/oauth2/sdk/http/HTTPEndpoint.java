package com.nimbusds.oauth2.sdk.http;


/**
 * HTTP endpoint.
 *
 * @author Vladimir Dzhuvinov
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