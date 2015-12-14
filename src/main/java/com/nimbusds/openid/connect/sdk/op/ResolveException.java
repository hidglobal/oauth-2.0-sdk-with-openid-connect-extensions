package com.nimbusds.openid.connect.sdk.op;


import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCError;


/**
 * Resolve exception.
 */
public class ResolveException extends GeneralException {


	/**
	 * Creates a new resolve exception.
	 *
	 * @param error       The associated OpenID Connect / OAuth 2.0 error.
	 *                    Must not be {@code null}.
	 * @param authRequest The associated OpenID Connect authentication
	 *                    request. Must not be {@code null}.
	 */
	public ResolveException(final ErrorObject error, final AuthenticationRequest authRequest) {

		super(null,
			error,
			authRequest.getClientID(),
			authRequest.getRedirectionURI(),
			authRequest.getResponseMode(),
			authRequest.getState(),
			null);
	}


	/**
	 * Creates a new resolve exception.
	 *
	 * @param exMessage     The original exception message (to be logged).
	 *                      May be {@code null}.
	 * @param clientMessage The message to pass back to the client in the
	 *                      {@code error_description} of the error code,
	 *                      {@code null} to use the default one.
	 * @param authRequest   The associated OpenID Connect authentication
	 *                      request, used to determine the error object.
	 *                      Must not be {@code null}.
	 * @param cause         The exception cause, {@code null} if not
	 *                      specified.
	 */
	public ResolveException(final String exMessage,
				final String clientMessage,
				final AuthenticationRequest authRequest,
		                final Throwable cause) {

		super(exMessage,
			(authRequest.getRequestURI() != null ? OIDCError.REQUEST_URI_NOT_SUPPORTED : OIDCError.REQUEST_NOT_SUPPORTED)
				.setDescription(clientMessage != null ? clientMessage : "Request (URI) parameter not supported"),
			authRequest.getClientID(),
			authRequest.getRedirectionURI(),
			authRequest.getResponseMode(),
			authRequest.getState(),
			cause);
	}
}
