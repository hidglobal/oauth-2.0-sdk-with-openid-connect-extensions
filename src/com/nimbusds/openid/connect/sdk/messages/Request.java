package com.nimbusds.openid.connect.sdk.messages;


import com.nimbusds.openid.connect.sdk.SerializeException;

import com.nimbusds.openid.connect.sdk.http.HTTPRequest;


/**
 * Interface for OpenID Connect request messages.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-11)
 */
public interface Request extends Message {


	/**
	 * Returns the matching HTTP request.
	 *
	 * @return The HTTP request.
	 *
	 * @throws SerializeException If the OpenID Connect request message
	 *                            couldn't be serialised to an HTTP request.
	 */
	public HTTPRequest toHTTPRequest() throws SerializeException;
}


