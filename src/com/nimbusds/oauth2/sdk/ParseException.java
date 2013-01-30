package com.nimbusds.oauth2.sdk;


import java.net.URL;

import com.nimbusds.oauth2.sdk.id.State;


/**
 * Parse exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-30)
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
	 * Creates a new parse exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param error   The associated error, {@code null} if not specified.
	 */
	public ParseException(final String message, final ErrorObject error) {
	
		this(message, error, null);
	}


	/**
	 * Creates a new parse exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param error   The associated error, {@code null} if not specified.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public ParseException(final String message, 
		              final ErrorObject error,
		              final Throwable cause) {
	
		super(message, error, cause);
	}


	/**
	 * Creates a new parse exception.
	 *
	 * @param message     The exception message. May be {@code null}.
	 * @param error       The associated error, {@code null} if not
	 *                    specified.
	 * @param redirectURI The associated redirection URI, must not be 
	 *                    {@code null}.
	 * @param state       The optional associated state parameter, 
	 *                    {@code null} if not specified.
	 * @param cause       The exception cause, {@code null} if not
	 *                    specified.
	 */
	public ParseException(final String message, 
		              final ErrorObject error,
		              final URL redirectURI,
		              final State state,
		              final Throwable cause) {

		super(message, error, redirectURI, state, cause);
	}
}
