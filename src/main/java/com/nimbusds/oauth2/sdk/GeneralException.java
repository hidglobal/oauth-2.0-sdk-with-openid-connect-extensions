package com.nimbusds.oauth2.sdk;


import java.net.URI;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;


/**
 * The base class for exceptions defined in this SDK.
 */
public class GeneralException extends Exception {


	/**
	 * The associated error, {@code null} if not specified.
	 */
	private final ErrorObject error;


	/**
	 * The associated client identifier, {@code null} if not specified.
	 */
	private final ClientID clientID;


	/**
	 * The redirection URI, {@code null} if not specified or redirection is
	 * not to be performed for this error. Implies a HTTP status code 302.
	 */
	private final URI redirectURI;


	/**
	 * Optional response mode parameter, {@code null} if not specified.
	 */
	private final ResponseMode responseMode;


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
	
		this(message, null, null, null, null, null, null);
	}
	
	
	/**
	 * Creates a new general exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public GeneralException(final String message, final Throwable cause) {
	
		this(message, null, null, null, null, null, cause);
	}


	/**
	 * Creates a new general exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param error   The associated error, {@code null} if not specified.
	 */
	public GeneralException(final String message,
				final ErrorObject error) {

		this(message, error, null, null, null, null, null);
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
	
		this(message, error, null, null, null, null, cause);
	}
	
	
	/**
	 * Creates a new general exception.
	 *
	 * @param message      The exception message. May be {@code null}.
	 * @param error        The associated error, {@code null} if not
	 *                     specified.
	 * @param clientID     The associated client identifier, {@code null} if
	 *                     not specified.
	 * @param redirectURI  The associated redirection URI, {@code null} if
	 *                     not specified.
	 * @param responseMode The optional associated response mode,
	 *                     {@code null} if not specified.
	 * @param state        The optional associated state parameter,
	 *                     {@code null} if not specified.
	 */
	public GeneralException(final String message, 
		                final ErrorObject error,
				final ClientID clientID,
		                final URI redirectURI,
				final ResponseMode responseMode,
		                final State state) {
	
		this(message, error, clientID, redirectURI, responseMode, state, null);
	}


	/**
	 * Creates a new general exception.
	 *
	 * @param message      The exception message. May be {@code null}.
	 * @param error        The associated error, {@code null} if not
	 *                     specified.
	 * @param clientID     The associated client identifier, {@code null}
	 *                     if not specified.
	 * @param redirectURI  The associated redirection URI, {@code null} if
	 *                     not specified.
	 * @param state        The optional associated state parameter,
	 *                     {@code null} if not specified.
	 * @param responseMode The optional associated response mode,
	 *                     {@code null} if not specified.
	 * @param cause        The exception cause, {@code null} if not
	 *                     specified.
	 */
	public GeneralException(final String message, 
		                final ErrorObject error,
				final ClientID clientID,
		                final URI redirectURI,
				final ResponseMode responseMode,
		                final State state,
		                final Throwable cause) {
	
		super(message, cause);

		this.error = error;
		this.clientID = clientID;
		this.redirectURI = redirectURI;
		this.responseMode = responseMode;
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
	 * Gets the associated client identifier.
	 *
	 * @return The client ID, {@code null} if not specified.
	 */
	public ClientID getClientID() {

		return clientID;
	}


	/**
	 * Gets the associated redirection URI.
	 *
	 * @return The redirection URI, {@code null} if redirection is not to
	 *         be performed for this error.
	 */
	public URI getRedirectionURI() {

		return redirectURI;
	}


	/**
	 * Gets the associated response mode.
	 *
	 * @return The response mode, {@code null} if not specified.
	 */
	public ResponseMode getResponseMode() {

		return responseMode;
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
