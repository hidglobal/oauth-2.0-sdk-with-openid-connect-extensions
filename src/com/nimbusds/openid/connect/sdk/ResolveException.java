package com.nimbusds.openid.connect.sdk;


import java.net.URL;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.OAuth2Exception;

import com.nimbusds.oauth2.sdk.id.State;


/**
 * Resolve exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-21)
 */
public class ResolveException extends OAuth2Exception {


	/**
	 * Creates a new resolve exception.
	 *
	 * @param message   The exception message. May be {@code null}.
	 */
	public ResolveException(final String message) {
	
		super(message);
	}


	/**
	 * Creates a new resolve exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public ResolveException(final String message,
		                final Throwable cause) {
	
		super(message, cause);
	}


	/**
	 * Creates a new resolve exception. Implies a HTTP status code
	 * {@link #HTTP_SC_BAD_REQUEST 400}.
	 *
	 * @param message  The exception message. May be {@code null}.
	 * @param error    The associated OpenID Connect / OAuth 2.0 error, 
	 *                 {@code null} if not specified.
	 * @param cause    The exception cause, {@code null} if not specified.
	 */
	public ResolveException(final String message, 
		                final OAuth2Error error,
		                final Throwable cause) {
	
		super(message, error, cause);
	}


	/**
	 * Creates a new resolve exception. Implies a HTTP status code
	 * {@link #HTTP_SC_FOUND 302}.
	 *
	 * @param message     The exception message. May be {@code null}.
	 * @param error       The associated OpenID Connect / OAuth 2.0 error,
	 *                    {@code null} if not specified.
	 * @param redirectURI The associated redirection URI, must not be 
	 *                    {@code null}.
	 * @param state       The optional associated state parameter, 
	 *                    {@code null} if not specified.
	 * @param cause       The exception cause, {@code null} if not
	 *                    specified.
	 */
	public ResolveException(final String message, 
		                final OAuth2Error error,
		                final URL redirectURI,
		                final State state,
		                final Throwable cause) {

		super(message, error, redirectURI, state, cause);
	}
}
