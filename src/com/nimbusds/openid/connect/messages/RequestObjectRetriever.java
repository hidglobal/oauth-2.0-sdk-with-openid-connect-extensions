package com.nimbusds.openid.connect.messages;


import java.io.IOException;

import java.net.URL;

import com.nimbusds.jose.JOSEObject;

import com.nimbusds.openid.connect.ParseException;


/**
 * Retriever of OpenID Connect request objects referenced by URL.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-11)
 */
public interface RequestObjectRetriever {


	/**
	 * Downloads a JOSE-encoded OpenID Connect request object at the 
	 * specified URL.
	 *
	 * @param url The request object URL. Must not be {@code null}.
	 *
	 * @throws IOException    If the HTTP connection to the specified URL 
	 *                        failed.
	 * @throws ParseException If the content at the specified URL couldn't
	 *                        be parsed to a valid JOSE object.
	 */
	public JOSEObject downloadRequestObject(final URL url)
		throws IOException, ParseException;
}
