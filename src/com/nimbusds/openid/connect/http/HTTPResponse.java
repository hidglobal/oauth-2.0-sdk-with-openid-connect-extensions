package com.nimbusds.openid.connect.http;


import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;

import javax.mail.internet.ContentType;

import javax.servlet.http.HttpServletResponse;

import com.nimbusds.openid.connect.ParseException;

import com.nimbusds.openid.connect.util.ContentTypeUtils;


/**
 * HTTP response with support for all parameters required to construct an OpenID
 * Connect {@link com.nimbusds.openid.connect.messages.Response response 
 * message}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-11)
 */
public class HTTPResponse {

	
	/**
	 * HTTP status code (200) indicating the request succeeded normally.
	 */
	public static final int SC_OK = 200;
	
	
	/**
	 * HTTP status code (302) indicating that the resource reside 
	 * temporarily under a different URI (redirect).
	 */
	public static final int SC_FOUND = 302;
	
	
	/**
	 * HTTP status code (400) indicating a bad request.
	 */
	public static final int SC_BAD_REQUEST = 400;
	
	
	/**
	 * HTTP status code (401) indicating that the request requires HTTP 
	 * authentication.
	 */
	public static final int SC_UNAUTHORIZED = 401;
	
	
	/**
	 * HTTP status code (403) indicating that access to the resource was
	 * forbidden.
	 */
	public static final int SC_FORBIDDEN = 403;


	/**
	 * The HTTP status code.
	 */
	private int statusCode;
	
	
	/**
	 * Specifies a {@code Location} header value (for redirects).
	 */
	private URL location = null;
	
	
	/**
	 * Specifies a {@code Content-Type} header value.
	 */
	private ContentType contentType = null;
	
	
	/**
	 * Specifies a {@code Cache-Control} header value.
	 */
	private String cacheControl = null;
	
	
	/**
	 * Specifies a {@code Pragma} header value.
	 */
	private String pragma = null;
	
	
	/**
	 * Specifies a {@code Www-Authenticate} header value.
	 */
	private String wwwAuthenticate = null;
	
	
	/**
	 * The response content.
	 */
	private String content = null;
	
	
	/**
	 * Creates a new minimal HTTP response with the specified status code.
	 *
	 * @param statusCode The HTTP status code.
	 */
	public HTTPResponse(final int statusCode) {
	
		this.statusCode = statusCode;
	}
	
	
	/**
	 * Gets the HTTP status code.
	 *
	 * @return The HTTP status code.
	 */
	public int getStatusCode() {
	
		return statusCode;
	}
	
	
	/**
	 * Sets the HTTP status code.
	 *
	 * @param statusCode The HTTP status code.
	 */
	public void setStatusCode(final int statusCode) {
	
		this.statusCode = statusCode;
	}
	
	
	/**
	 * Gets the {@code Location} header value (for redirects).
	 *
	 * @return The header value, {@code null} if not specified.
	 */
	public URL getLocation() {
	
		return location;
	}
	
	
	/**
	 * Sets the {@code Location} header value (for redirects).
	 *
	 * @param location The header value, {@code null} if not specified.
	 */
	public void setLocation(final URL location) {
	
		this.location = location;
	}
	
	
	/**
	 * Gets the {@code Content-Type} header value.
	 *
	 * @return The header value, {@code null} if not specified.
	 */
	public ContentType getContentType() {
	
		return contentType;
	}
	
	
	/**
	 * Sets the {@code Content-Type} header value.
	 *
	 * @param contentType The header value, {@code null} if not specified.
	 */
	public void setContentType(final ContentType contentType) {
	
		this.contentType = contentType;
	}
	
	
	/**
	 * Ensures this HTTP response has the specified {@code Content-Type} 
	 * header value. Note that this method compares only the primary type 
	 * and subtype; any content type parameters, such as {@code charset}, 
	 * are ignored.
	 *
	 * @param contentType The expected content type. Must not be 
	 *                    {@code null}.
	 *
	 * @throws ParseException If the {@code Content-Type} header is missing
	 *                        or its primary and subtype doesn't match.
	 */ 
	public void ensureContentType(final ContentType contentType)
		throws ParseException {
		
		ContentTypeUtils.ensureContentType(contentType, getContentType());
	}
	
	
	/**
	 * Gets the {@code Cache-Control} header value.
	 *
	 * @return The header value, {@code null} if not specified.
	 */
	public String getCacheControl() {
	
		return cacheControl;
	}


	/**
	 * Sets the {@code Cache-Control} header value.
	 *
	 * @param cacheControl The header value, {@code null} if not specified.
	 */
	public void setCacheControl(final String cacheControl) {
	
		this.cacheControl = cacheControl;
	}
	
	
	/**
	 * Gets the {@code Pragma} header value.
	 *
	 * @return The header value, {@code null} if not specified.
	 */
	public String getPragma() {
	
		return pragma;
	}
	
	
	/**
	 * Sets the {@code Pragma} header value.
	 *
	 * @param pragma The header value, {@code null} if not specified.
	 */
	public void setPragma(final String pragma) {
	
		this.pragma = pragma;
	}
	
	
	/**
	 * Gets the {@code Www-Authenticate} header value.
	 *
	 * @return The header value, {@code null} if not specified.
	 */
	public String getWWWAuthenticate() {
	
		return wwwAuthenticate;
	}
	
	
	/**
	 * Sets the {@code Www-Authenticate} header value.
	 *
	 * @param wwwAuthenticate The header value, {@code null} if not 
	 *                        specified.
	 */
	public void setWWWAuthenticate(final String wwwAuthenticate) {
	
		this.wwwAuthenticate = wwwAuthenticate;
	}
	
	
	/**
	 * Gets the response content.
	 *
	 * @return The response content, {@code null} if none.
	 */
	public String getContent() {
	
		return content;
	}
	
	
	/**
	 * Sets the response content.
	 *
	 * @param content The response content, {@code null} if none.
	 */
	public void setContent(final String content) {
	
		this.content = content;
	}
	
	
	/**
	 * Applies the status code, headers and content of this HTTP response
	 * object to the specified HTTP servlet response.
	 *
	 * @param sr The HTTP servlet response to apply. Must not be 
	 *           {@code null}.
	 *
	 * @throws IOException If the response content couldn't be written.
	 */
	public void apply(final HttpServletResponse sr)
		throws IOException {
	
		// Set the status code
		sr.setStatus(statusCode);
	
	
		// Set the headers, but only if explicitly specified	
		if (location != null)
			sr.setHeader("Location", location.toString());
		
		if (contentType != null)
			sr.setContentType(contentType.toString());
		
		if (cacheControl != null)
			sr.setHeader("Cache-Control", cacheControl);
		
		if (pragma != null)
			sr.setHeader("Pragma", pragma);
		
		
		if (wwwAuthenticate != null)
			sr.setHeader("Www-Authenticate", wwwAuthenticate);
	
	
		// Write out the content
	
		if (content != null) {
		
			PrintWriter writer = sr.getWriter();
		
			writer.println(content);
			
			writer.close();
		}
	}
}
