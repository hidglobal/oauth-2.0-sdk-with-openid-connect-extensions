package com.nimbusds.openid.connect.messages;


import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.HTTPRequest;


/**
 * Interface for OpenID Connect request messages.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-05-11)
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


