package com.nimbusds.oauth2.sdk;


import java.net.URL;

import com.nimbusds.oauth2.sdk.id.State;


/**
 * The base class for exceptions defined in this SDK.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-30)
 */
public class GeneralException extends Exception {


	/**
	 * The associated error, {@code null} if not specified.
	 */
	private final ErrorObject error;


	/**
	 * The redirection URI, {@code null} if not specified or redirection is
	 * not to be performed for this error. Implies a HTTP status code 302.
	 */
	private final URL redirectURI;


	/**
	 * Optional state parameter, {@code null} if not specified.
	 */
	private final State state;


	/**
	 * Creates a new general exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 */
	public GeneralException(final String message) {
	
		this(message, null);
	}
	
	
	/**
	 * Creates a new general exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public GeneralException(final String message, final Throwable cause) {
	
		this(message, null, cause);
	}


	/**
	 * Creates a new general exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param error   The associated error, {@code null} if not specified.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public GeneralException(final String message, 
		                final ErrorObject error,
		                final Throwable cause) {
	
		this(message, error, null, null, cause);
	}


	/**
	 * Creates a new general exception.
	 *
	 * @param message     The exception message. May be {@code null}.
	 * @param error       The associated error, {@code null} if not 
	 *                    specified.
	 * @param redirectURI The associated redirection URI, {@code null} if
	 *                    not specified.
	 * @param state       The optional associated state parameter, 
	 *                    {@code null} if not specified.
	 * @param cause       The exception cause, {@code null} if not
	 *                    specified.
	 */
	public GeneralException(final String message, 
		                final ErrorObject error,
		                final URL redirectURI,
		                final State state,
		                final Throwable cause) {
	
		super(message, cause);

		this.error = error;
		this.redirectURI = redirectURI;
		this.state = state;
	}


	/**
	 * Gets the associated error.
	 *
	 * @return The error, {@code null} if not specified.
	 */
	public ErrorObject getErrorObject() {

		return error;
	}


	/**
	 * Gets the associated redirection URI. 
	 * 
	 * <p>Important: Must be verified with the client registry before 
	 * acting upon it!
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
