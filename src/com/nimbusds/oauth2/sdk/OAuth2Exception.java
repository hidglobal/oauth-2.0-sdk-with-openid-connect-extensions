package com.nimbusds.oauth2.sdk;


import java.net.URL;

import com.nimbusds.oauth2.sdk.id.State;


/**
 * General OAuth 2.0 exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-28)
 */
public class OAuth2Exception extends Exception {


	/**
	 * The associated OAuth 2.0 error, {@code null} if not specified.
	 */
	private final OAuth2Error error;


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
	 * Creates a new OAuth 2.0 exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 */
	public OAuth2Exception(final String message) {
	
		this(message, null);
	}
	
	
	/**
	 * Creates a new OAuth 2.0 exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public OAuth2Exception(final String message, final Throwable cause) {
	
		this(message, null, cause);
	}


	/**
	 * Creates a new OAuth 2.0 exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param error   The associated OAuth 2.0 error, {@code null} if not
	 *                specified.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public OAuth2Exception(final String message, 
		               final OAuth2Error error,
		               final Throwable cause) {
	
		this(message, error, null, null, cause);
	}


	/**
	 * Creates a new OAuth 2.0 exception.
	 *
	 * @param message     The exception message. May be {@code null}.
	 * @param error       The associated OAuth 2.0 error, {@code null} if
	 *                    not specified.
	 * @param redirectURI The associated redirection URI, {@code null} if
	 *                    not specified.
	 * @param state       The optional associated state parameter, 
	 *                    {@code null} if not specified.
	 * @param cause       The exception cause, {@code null} if not
	 *                    specified.
	 */
	public OAuth2Exception(final String message, 
		               final OAuth2Error error,
		               final URL redirectURI,
		               final State state,
		               final Throwable cause) {
	
		super(message, cause);

		this.error = error;
		this.redirectURI = redirectURI;
		this.state = state;
	}


	/**
	 * Gets the associated OAuth 2.0 error.
	 *
	 * @return The OAuth 2.0 error, {@code null} if not specified.
	 */
	public OAuth2Error getOAuth2Error() {

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
