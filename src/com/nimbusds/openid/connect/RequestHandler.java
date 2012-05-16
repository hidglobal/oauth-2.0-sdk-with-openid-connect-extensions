package com.nimbusds.openid.connect;


import com.nimbusds.openid.connect.messages.Request;
import com.nimbusds.openid.connect.messages.Response;


/**
 * Endpoint handler for OpenID Connect {@link Request}s. Performs the actual
 * request processing  (e.g. by making a database query).
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-03-14)
 */
public interface RequestHandler {


	/**
	 *
	 */
	public Response process(final Request request);

}
