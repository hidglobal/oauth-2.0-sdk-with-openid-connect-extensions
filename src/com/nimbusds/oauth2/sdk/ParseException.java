package com.nimbusds.oauth2.sdk;


import java.net.URL;


/**
 * Parse exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-15)
 */
public class ParseException extends OAuth2Exception {


	/**
	 * Creates a new parse exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 */
	public ParseException(final String message) {
	
		this(message, null, null);
	}
	
	
	/**
	 * Creates a new parse exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public ParseException(final String message, final Throwable cause) {
	
		this(message, null, cause);
	}


	/**
	 * Creates a new parse exception. Implies a HTTP status code
	 * {@link #HTTP_SC_BAD_REQUEST 400}.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param error   The associated OAuth 2.0 error, {@code null} if not
	 *                specified.
	 */
	public ParseException(final String message, final OAuth2Error error) {
	
		this(message, error, null);
	}


	/**
	 * Creates a new parse exception. Implies a HTTP status code
	 * {@link #HTTP_SC_BAD_REQUEST 400}.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param error   The associated OAuth 2.0 error, {@code null} if not
	 *                specified.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public ParseException(final String message, 
		              final OAuth2Error error,
		              final Throwable cause) {
	
		super(message, error, cause);
	}


	/**
	 * Creates a new parse exception. Implies a HTTP status code
	 * {@link #HTTP_SC_FOUND 302}.
	 *
	 * @param message     The exception message. May be {@code null}.
	 * @param error       The associated OAuth 2.0 error, {@code null} if
	 *                    not specified.
	 * @param redirectURI The associated redirection URI, must not be 
	 *                    {@code null}.
	 * @param state       The optional associated state parameter, 
	 *                    {@code null} if not specified.
	 * @param cause       The exception cause, {@code null} if not
	 *                    specified.
	 */
	public ParseException(final String message, 
		              final OAuth2Error error,
		              final URL redirectURI,
		              final State state,
		              final Throwable cause) {

		super(message, error, redirectURI, state, cause);
	}
}
