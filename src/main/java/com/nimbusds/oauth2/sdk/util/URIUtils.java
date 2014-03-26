package com.nimbusds.oauth2.sdk.util;


import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;


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
	 * Gets the base part (schema, host, port and path) of the specified
	 * URL as an URI.
	 *
	 * @param url The URL. May be {@code null}.
	 *
	 * @return The base part of the URL as an URI, {@code null} if the
	 *         original URL is {@code null} or doesn't specify a protocol.
	 */
	public static URI getBaseURI(final URL url) {

		if (url == null)
			return null;

		try {
			return new URI(url.getProtocol(), null, url.getHost(), url.getPort(), url.getPath(), null, null);

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
