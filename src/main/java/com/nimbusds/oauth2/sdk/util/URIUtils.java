package com.nimbusds.oauth2.sdk.util;


import java.net.URI;
import java.net.URISyntaxException;


/**
 * URI operations.
 */
public class URIUtils {


	/**
	 * Gets the base part (schema, host, port and path) of the specified
	 * URI.
	 *
	 * @param uri The URI. May be {@code null}.
	 *
	 * @return The base part of the URI, {@code null} if the original URI
	 *         is {@code null} or doesn't specify a protocol.
	 */
	public static URI getBaseURI(final URI uri) {

		if (uri == null)
			return null;

		try {
			return new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), uri.getPath(), null, null);

		} catch (URISyntaxException e) {

			return null;
		}
	}


	/**
	 * Prevents instantiation.
	 */
	private URIUtils() {

		// do nothing
	}
}
