package com.nimbusds.openid.connect.sdk;


import java.net.URL;

import com.nimbusds.openid.connect.sdk.messages.ErrorCode;
import com.nimbusds.openid.connect.sdk.messages.State;


/**
 * General OpenID Connect exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-27)
 */
public class OpenIDConnectException extends Exception {


	/**
	 * HTTP status code 302 (Found).
	 */
	public static final int HTTP_SC_FOUND = 302;


	/**
	 * HTTP status code 400 (Bad Request).
	 */
	public static final int HTTP_SC_BAD_REQUEST = 400;


	/**
	 * The associated OpenID Connect error code, {@code null} if not
	 * specified.
	 */
	private final ErrorCode errorCode;


	/**
	 * The associated HTTP status code, 0 if not specified.
	 */
	private final int httpStatusCode;


	/**
	 * The redirection URI, {@code null} if not specified or redirection is
	 * not to be performed for this error. Implies a HTTP status code 302.
	 */
	private URL redirectURI;


	/**
	 * Optional state parameter, {@code null} if not specified.
	 */
	private State state;


	/**
	 * Creates a new OpenID Connect exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 */
	public OpenIDConnectException(final String message) {
	
		this(message, null);
	}
	
	
	/**
	 * Creates a new OpenID Connect exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public OpenIDConnectException(final String message, 
		                      final Throwable cause) {
	
		super(message, cause);

		errorCode = null;

		httpStatusCode = 0;
	}


	/**
	 * Creates a new OpenID Connect exception. Implies a HTTP status code
	 * {@link #HTTP_SC_BAD_REQUEST 400}.
	 *
	 * @param message   The exception message. May be {@code null}.
	 * @param errorCode The associated OpenID Connect / OAuth 2.0 error 
	 *                  code, {@code null} if not specified.
	 * @param cause     The exception cause, {@code null} if not specified.
	 */
	public OpenIDConnectException(final String message, 
		                      final ErrorCode errorCode,
		                      final Throwable cause) {
	
		super(message, cause);

		this.errorCode = errorCode;

		httpStatusCode = HTTP_SC_BAD_REQUEST;
	}


	/**
	 * Creates a new OpenID Connect exception. Implies a HTTP status code
	 * {@link #HTTP_SC_FOUND 302}.
	 *
	 * @param message     The exception message. May be {@code null}.
	 * @param errorCode   The associated OpenID Connect / OAuth 2.0 
	 *                    error code, {@code null} if not specified.
	 * @param redirectURI The associated redirection URI, must not be 
	 *                    {@code null}.
	 * @param state       The optional associated state parameter, 
	 *                    {@code null} if not specified.
	 * @param cause       The exception cause, {@code null} if not
	 *                    specified.
	 */
	public OpenIDConnectException(final String message, 
		                      final ErrorCode errorCode,
		                      final URL redirectURI,
		                      final State state,
		                      final Throwable cause) {
	
		super(message, cause);

		this.errorCode = errorCode;

		httpStatusCode = HTTP_SC_FOUND;

		if (redirectURI == null)
			throw new IllegalArgumentException("The redirection URI must not be null");

		this.redirectURI = redirectURI;

		this.state = state;
	}


	/**
	 * Gets the associated OpenID Connect / OAuth 2.0 error code.
	 *
	 * @return The OpenID Connect / OAuth 2.0 error code, {@code null} if
	 *         not specified.
	 */
	public ErrorCode getErrorCode() {

		return errorCode;
	}


	/**
	 * Gets the associated HTTP status code.
	 *
	 * @return The HTTP status code, with possible values 
	 *         {@link #HTTP_SC_FOUND 302}, {@link #HTTP_SC_BAD_REQUEST 400}
	 *         or 0 if not specified.
	 */
	public int getHTTPStatusCode() {

		return httpStatusCode;
	}


	/**
	 * Gets the associated redirection URI.
	 *
	 * @return The redirection URI, {@code null} if redirection is not to
	 *         be performed for this error.
	 */
	public URL getRedirectURI() {

		return redirectURI;
	}


	/**
	 * Gets the optional associated state parameter.
	 *
	 * @return The optional state parameter, {@code null} if not specified 
	 *         or redirection is not to be performed.
	 */
	public State getState() {

		return state;
	}
}
