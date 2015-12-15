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

		super(error.getDescription(),
			error,
			authRequest.getClientID(),
			authRequest.getRedirectionURI(),
			authRequest.getResponseMode(),
			authRequest.getState(),
			null);
	}


	/**
	 * Creates a new resolve exception. The error code is set to
	 * {@link OIDCError#INVALID_REQUEST_URI} or
	 * {@link OIDCError#INVALID_REQUEST_OBJECT} depending on the request
	 * type.
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
			resolveErrorObject(clientMessage, authRequest),
			authRequest.getClientID(),
			authRequest.getRedirectionURI(),
			authRequest.getResponseMode(),
			authRequest.getState(),
			cause);
	}


	/**
	 * Resolves the error object ({@code invalid_request_uri} or
	 * {@code invalid_request_object}) for the specified OpenID
	 * authentication request.
	 *
	 * @param clientMessage The message to pass back to the client in the
	 *                      {@code error_description} of the error code,
	 *                      {@code null} to use the default one.
	 * @param authRequest   The associated OpenID Connect authentication
	 *                      request, used to determine the error object.
	 *                      Must not be {@code null}.
	 *
	 * @return The error object.
	 */
	private static ErrorObject resolveErrorObject(final String clientMessage,
						      final AuthenticationRequest authRequest) {

		ErrorObject errorObject;

		if (authRequest.getRequestURI() != null) {
			errorObject = OIDCError.INVALID_REQUEST_URI;
		} else {
			errorObject = OIDCError.INVALID_REQUEST_OBJECT;
		}

		if (clientMessage != null) {
			return errorObject.setDescription(clientMessage);
		}

		return errorObject;
	}
}
