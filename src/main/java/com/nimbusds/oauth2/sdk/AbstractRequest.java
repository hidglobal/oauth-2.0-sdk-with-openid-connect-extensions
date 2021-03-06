package com.nimbusds.oauth2.sdk;


import java.net.URI;


/**
 * The base abstract class for requests.
 */
public abstract class AbstractRequest implements Request {
	
	
	/**
	 * The request endpoint.
	 */
	private final URI uri;
	
	
	/**
	 * Creates a new base abstract request.
	 * 
	 * @param uri The URI of the endpoint (HTTP or HTTPS) for which the 
	 *            request is intended, {@code null} if not specified (if,
	 *            for example, the {@link #toHTTPRequest()} method will not
	 *            be used).
	 */
	public AbstractRequest(final URI uri) {
		
		this.uri = uri;
	}
	
	
	@Override
	public URI getEndpointURI() {
		
		return uri;
	}
}
