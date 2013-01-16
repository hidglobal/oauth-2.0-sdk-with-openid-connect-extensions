package com.nimbusds.oauth2.sdk;


import com.nimbusds.oauth2.sdk.http.HTTPRequest;


/**
 * OAuth 2.0 request message.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-16)
 */
public interface OAuth2Request extends OAuth2Message {


	/**
	 * Returns the matching HTTP request.
	 *
	 * @return The HTTP request.
	 *
	 * @throws SerializeException If the OAuth 2.0 request message couldn't
	 *                            be serialised to an HTTP request.
	 */
	public HTTPRequest toHTTPRequest() 
		throws SerializeException;
}


