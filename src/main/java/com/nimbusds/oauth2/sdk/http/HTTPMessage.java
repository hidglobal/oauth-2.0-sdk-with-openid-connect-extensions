package com.nimbusds.oauth2.sdk.http;


import javax.mail.internet.ContentType;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.ContentTypeUtils;


/**
 * The base abstract class for HTTP requests and responses.
 *
 * @author Vladimir Dzhuvinov
 */
abstract class HTTPMessage {


	/**
	 * Specifies a {@code Content-Type} header value.
	 */
	private ContentType contentType = null;


	/**
	 * Gets the {@code Content-Type} header value.
	 *
	 * @return The {@code Content-Type} header value, {@code null} if not 
	 *         specified.
	 */
	public ContentType getContentType() {
	
		return contentType;
	}
	
	
	/**
	 * Sets the {@code Content-Type} header value.
	 *
	 * @param ct The {@code Content-Type} header value, {@code null} if not
	 *           specified.
	 */
	public void setContentType(final ContentType ct) {
	
		contentType = ct;
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
		
		if (ct == null) {
			contentType = null;
			return;
		}
		
		try {
			contentType = new ContentType(ct);
			
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
	
		if (contentType == null)
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
}