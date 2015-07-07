package com.nimbusds.openid.connect.sdk.op;


import java.net.URI;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;


/**
 * Resolve exception.
 */
public class ResolveException extends GeneralException {


	/**
	 * Creates a new resolve exception.
	 *
	 * @param message   The exception message. May be {@code null}.
	 */
	public ResolveException(final String message) {
	
		this(message, null, null, null, null, null, null);
	}


	/**
	 * Creates a new resolve exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public ResolveException(final String message,
		                final Throwable cause) {
	
		this(message, null, null, null, null, null, cause);
	}


	/**
	 * Creates a new resolve exception.
	 *
	 * @param message  The exception message. May be {@code null}.
	 * @param error    The associated OpenID Connect / OAuth 2.0 error, 
	 *                 {@code null} if not specified.
	 * @param cause    The exception cause, {@code null} if not specified.
	 */
	public ResolveException(final String message, 
		                final ErrorObject error,
		                final Throwable cause) {
	
		this(message, error, null, null, null, null, cause);
	}


	/**
	 * Creates a new resolve exception.
	 *
	 * @param message      The exception message. May be {@code null}.
	 * @param error        The associated OpenID Connect / OAuth 2.0 error,
	 *                     {@code null} if not specified.
	 * @param clientID     The associated client identifier. Must not be
	 *                     {@code null}.
	 * @param redirectURI  The associated redirection URI. Must not be
	 *                     {@code null}.
	 * @param responseMode The optional associated response mode,
	 *                     {@code null} if not specified.
	 * @param state        The optional associated state parameter,
	 *                     {@code null} if not specified.
	 * @param cause        The exception cause, {@code null} if not
	 *                     specified.
	 */
	public ResolveException(final String message, 
		                final ErrorObject error,
				final ClientID clientID,
		                final URI redirectURI,
				final ResponseMode responseMode,
		                final State state,
		                final Throwable cause) {

		super(message, error, clientID, redirectURI, responseMode, state, cause);
	}
}
