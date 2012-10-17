package com.nimbusds.openid.connect.util;


import java.io.IOException;

import java.net.URL;

import com.nimbusds.jose.JOSEObject;

import com.nimbusds.openid.connect.ParseException;


/**
 * Retriever of Javascript Object Signing and Encryption (JOSE) objects passed 
 * by HTTP URL reference.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-17)
 */
public interface JOSEObjectRetriever {


	/**
	 * Downloads a JOSE object from the specified HTTP URL.
	 *
	 * @param url The URL of the JOSE object. Must not be {@code null}.
	 *
	 * @return The downloaded JOSE object.
	 *
	 * @throws IOException    If the HTTP connection to the specified URL 
	 *                        failed.
	 * @throws ParseException If the content at the specified URL couldn't
	 *                        be parsed to a valid JOSE object.
	 */
	public JOSEObject downloadJOSEObject(final URL url)
		throws IOException, ParseException;
}
