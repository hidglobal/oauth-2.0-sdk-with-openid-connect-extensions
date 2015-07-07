package com.nimbusds.oauth2.sdk.http;


import java.util.Map;
import java.util.TreeMap;
import javax.mail.internet.ContentType;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.ContentTypeUtils;


/**
 * The base abstract class for HTTP requests and responses.
 */
abstract class HTTPMessage {


	/**
	 * The HTTP request / response headers.
	 */
	private final Map<String,String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);


	/**
	 * Gets the {@code Content-Type} header value.
	 *
	 * @return The {@code Content-Type} header value, {@code null} if not 
	 *         specified.
	 */
	public ContentType getContentType() {

		final String value = getHeader("Content-Type");

		if (value == null) {
			return null;
		}

		try {
			return new ContentType(value);

		} catch (javax.mail.internet.ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Sets the {@code Content-Type} header value.
	 *
	 * @param ct The {@code Content-Type} header value, {@code null} if not
	 *           specified.
	 */
	public void setContentType(final ContentType ct) {

		setHeader("Content-Type", ct != null ? ct.toString() : null);
	}
	
	
	/**
	 * Sets the {@code Content-Type} header value.
	 *
	 * @param ct The {@code Content-Type} header value, {@code null} if not
	 *           specified.
	 *
	 * @throws ParseException If the header value couldn't be parsed to a
	 *                        valid content type.
	 */
	public void setContentType(final String ct)
		throws ParseException {
		
		try {
			setHeader("Content-Type", ct != null ? new ContentType(ct).toString() : null);
			
		} catch (javax.mail.internet.ParseException e) {
		
			throw new ParseException("Invalid Content-Type value: " + e.getMessage());
		}
	}
	
	
	/**
	 * Ensures this HTTP message has a {@code Content-Type} header value.
	 *
	 * @throws ParseException If the {@code Content-Type} header is 
	 *                        missing.
	 */
	public void ensureContentType()
		throws ParseException {
	
		if (getContentType() == null)
			throw new ParseException("Missing HTTP Content-Type header");
	}


	/**
	 * Ensures this HTTP message has the specified {@code Content-Type} 
	 * header value. This method compares only the primary type and 
	 * subtype; any content type parameters, such as {@code charset}, are
	 * ignored.
	 *
	 * @param contentType The expected content type. Must not be 
	 *                    {@code null}.
	 *
	 * @throws ParseException If the {@code Content-Type} header is missing
	 *                        or its primary and subtype don't match.
	 */ 
	public void ensureContentType(final ContentType contentType)
		throws ParseException {
		
		ContentTypeUtils.ensureContentType(contentType, getContentType());
	}


	/**
	 * Gets a HTTP header value.
	 *
	 * @param name The header name. Must not be {@code null}.
	 *
	 * @return The header value, {@code null} if not specified.
	 */
	public String getHeader(final String name) {

		return headers.get(name);
	}


	/**
	 * Sets a HTTP header value.
	 *
	 * @param name  The header name. Must not be {@code null}.
	 * @param value The header value. If {@code null} and a header with the
	 *              same name is specified, it will be deleted.
	 */
	public void setHeader(final String name, final String value) {

		if (value != null) {
			headers.put(name, value);
		} else {
			headers.remove(name);
		}
	}


	/**
	 * Returns the HTTP headers.
	 *
	 * @return The HTTP headers.
	 */
	public Map<String,String> getHeaders() {

		return headers;
	}
}