package com.nimbusds.oauth2.sdk;


import java.net.URI;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Error object, used to encapsulate OAuth 2.0 and other errors.
 *
 * <p>Example error object as HTTP response:
 *
 * <pre>
 * HTTP/1.1 400 Bad Request
 * Content-Type: application/json;charset=UTF-8
 * Cache-Control: no-store
 * Pragma: no-cache
 *
 * {
 *   "error" : "invalid_request"
 * }
 * </pre>
 */
@Immutable
public final class ErrorObject {
	
	
	/**
	 * The error code, may not always be defined.
	 */
	private final String code;


	/**
	 * Optional error description.
	 */
	private final String description;


	/**
	 * Optional HTTP status code, 0 if not specified.
	 */
	private final int httpStatusCode;


	/**
	 * Optional URI of a web page that includes additional information 
	 * about the error.
	 */
	private final URI uri;


	/**
	 * Creates a new error with the specified code.
	 *
	 * @param code The error code, {@code null} if not specified.
	 */
	public ErrorObject(final String code) {
	
		this(code, null, 0, null);
	}
	
	
	/**
	 * Creates a new error with the specified code and description.
	 *
	 * @param code        The error code, {@code null} if not specified.
	 * @param description The error description, {@code null} if not
	 *                    specified.
	 */
	public ErrorObject(final String code, final String description) {
	
		this(code, description, 0, null);
	}


	/**
	 * Creates a new error with the specified code, description and HTTP 
	 * status code.
	 *
	 * @param code           The error code, {@code null} if not specified.
	 * @param description    The error description, {@code null} if not
	 *                       specified.
	 * @param httpStatusCode The HTTP status code, zero if not specified.
	 */
	public ErrorObject(final String code, final String description, 
		           final int httpStatusCode) {
	
		this(code, description, httpStatusCode, null);
	}


	/**
	 * Creates a new error with the specified code, description, HTTP 
	 * status code and page URI.
	 *
	 * @param code           The error code, {@code null} if not specified.
	 * @param description    The error description, {@code null} if not
	 *                       specified.
	 * @param httpStatusCode The HTTP status code, zero if not specified.
	 * @param uri            The error page URI, {@code null} if not
	 *                       specified.
	 */
	public ErrorObject(final String code, final String description, 
		           final int httpStatusCode, final URI uri) {
	
		this.code = code;
		this.description = description;
		this.httpStatusCode = httpStatusCode;
		this.uri = uri;
	}


	/**
	 * Gets the error code.
	 *
	 * @return The error code, {@code null} if not specified.
	 */
	public String getCode() {

		return code;
	}
	
	
	/**
	 * Gets the error description.
	 *
	 * @return The error description, {@code null} if not specified.
	 */
	public String getDescription() {
	
		return description;
	}


	/**
	 * Sets the error description.
	 *
	 * @param description The error description, {@code null} if not 
	 *                    specified.
	 *
	 * @return A copy of this error with the specified description.
	 */
	public ErrorObject setDescription(final String description) {

		return new ErrorObject(getCode(), description, getHTTPStatusCode(), getURI());
	}


	/**
	 * Appends the specified text to the error description.
	 *
	 * @param text The text to append to the error description, 
	 *             {@code null} if not specified.
	 *
	 * @return A copy of this error with the specified appended 
	 *         description.
	 */
	public ErrorObject appendDescription(final String text) {

		String newDescription;

		if (getDescription() != null)
			newDescription = getDescription() + text;
		else
			newDescription = text;

		return new ErrorObject(getCode(), newDescription, getHTTPStatusCode(), getURI());
	}


	/**
	 * Gets the HTTP status code.
	 *
	 * @return The HTTP status code, zero if not specified.
	 */
	public int getHTTPStatusCode() {

		return httpStatusCode;
	}


	/**
	 * Sets the HTTP status code.
	 *
	 * @param httpStatusCode  The HTTP status code, zero if not specified.
	 *
	 * @return A copy of this error with the specified HTTP status code.
	 */
	public ErrorObject setHTTPStatusCode(final int httpStatusCode) {

		return new ErrorObject(getCode(), getDescription(), httpStatusCode, getURI());
	}


	/**
	 * Gets the error page URI.
	 *
	 * @return The error page URI, {@code null} if not specified.
	 */
	public URI getURI() {

		return uri;
	}


	/**
	 * Sets the error page URI.
	 *
	 * @param uri The error page URI, {@code null} if not specified.
	 *
	 * @return A copy of this error with the specified page URI.
	 */
	public ErrorObject setURI(final URI uri) {

		return new ErrorObject(getCode(), getDescription(), getHTTPStatusCode(), uri);
	}


	/**
	 * Returns a JSON object representation of this error object.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "error"             : "invalid_grant",
	 *   "error_description" : "Invalid resource owner credentials"
	   }
	 * </pre>
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();

		if (code != null) {
			o.put("error", code);
		}

		if (description != null) {
			o.put("error_description", description);
		}

		if (uri != null) {
			o.put("error_uri", uri.toString());
		}

		return o;
	}


	/**
	 * @see #getCode
	 */
	@Override
	public String toString() {
	
		if (code != null)
			return code;
		else
			return "null";
	}


	@Override
	public int hashCode() {
	
		if (code != null)
			return code.hashCode();
		else
			return "null".hashCode();
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof ErrorObject &&
		       this.toString().equals(object.toString());
	}


	/**
	 * Parses an error object from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The error object.
	 */
	public static ErrorObject parse(final JSONObject jsonObject) {

		String code = null;
		String description = null;
		URI uri = null;

		try {
			if (jsonObject.containsKey("error")) {
				code = JSONObjectUtils.getString(jsonObject, "error");
			}

			if (jsonObject.containsKey("error_description")) {
				description = JSONObjectUtils.getString(jsonObject, "error_description");
			}

			if (jsonObject.containsKey("error_uri")) {
				uri = JSONObjectUtils.getURI(jsonObject, "error_uri");
			}
		} catch (ParseException e) {
			// ignore and continue
		}

		return new ErrorObject(code, description, 0, uri);
	}


	/**
	 * Parses an error object from the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be
	 *                     {@code null}.
	 *
	 * @return The error object.
	 */
	public static ErrorObject parse(final HTTPResponse httpResponse) {

		JSONObject jsonObject;

		try {
			jsonObject = httpResponse.getContentAsJSONObject();

		} catch (ParseException e) {

			return new ErrorObject(null, null, httpResponse.getStatusCode());
		}

		ErrorObject intermediary = parse(jsonObject);

		return new ErrorObject(
			intermediary.getCode(),
			intermediary.description,
			httpResponse.getStatusCode(),
			intermediary.getURI());
	}
}
