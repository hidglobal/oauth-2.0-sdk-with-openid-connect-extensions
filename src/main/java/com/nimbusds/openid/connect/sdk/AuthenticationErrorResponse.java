package com.nimbusds.openid.connect.sdk;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.util.URLUtils;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * OpenID Connect authentication error response.
 *
 * <p>Standard errors:
 *
 * <ul>
 *     <li>OAuth 2.0 authorisation errors:
 *         <ul>
 *             <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#INVALID_REQUEST}
 *             <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#UNAUTHORIZED_CLIENT}
 *             <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#ACCESS_DENIED}
 *             <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#UNSUPPORTED_RESPONSE_TYPE}
 *             <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#INVALID_SCOPE}
 *             <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#SERVER_ERROR}
 *             <li>{@link com.nimbusds.oauth2.sdk.OAuth2Error#TEMPORARILY_UNAVAILABLE}
 *         </ul>
 *     <li>OpenID Connect specific errors:
 *         <ul>
 *             <li>{@link OIDCError#INTERACTION_REQUIRED}
 *             <li>{@link OIDCError#LOGIN_REQUIRED}
 *             <li>{@link OIDCError#ACCOUNT_SELECTION_REQUIRED}
 *             <li>{@link OIDCError#CONSENT_REQUIRED}
 *             <li>{@link OIDCError#INVALID_REQUEST_URI}
 *             <li>{@link OIDCError#INVALID_REQUEST_OBJECT}
 *             <li>{@link OIDCError#REGISTRATION_NOT_SUPPORTED}
 *             <li>{@link OIDCError#REQUEST_NOT_SUPPORTED}
 *             <li>{@link OIDCError#REQUEST_URI_NOT_SUPPORTED}
 *         </ul>
 *     </li>
 * </ul>
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 302 Found
 * Location: https://client.example.org/cb?
 *           error=invalid_request
 *           &amp;error_description=the%20request%20is%20not%20valid%20or%20malformed
 *           &amp;state=af0ifjsldkj
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 3.1.2.6.
 * </ul>
 */
@Immutable
public class AuthenticationErrorResponse
	extends AuthorizationErrorResponse
	implements AuthenticationResponse {


	/**
	 * The standard errors for an OpenID Connect authentication error
	 * response.
	 */
	private static Set<ErrorObject> stdErrors = new HashSet<>();
	
	
	static {
		stdErrors.addAll(AuthorizationErrorResponse.getStandardErrors());

		stdErrors.add(OIDCError.INTERACTION_REQUIRED);
		stdErrors.add(OIDCError.LOGIN_REQUIRED);
		stdErrors.add(OIDCError.ACCOUNT_SELECTION_REQUIRED);
		stdErrors.add(OIDCError.CONSENT_REQUIRED);
		stdErrors.add(OIDCError.INVALID_REQUEST_URI);
		stdErrors.add(OIDCError.INVALID_REQUEST_OBJECT);
		stdErrors.add(OIDCError.REGISTRATION_NOT_SUPPORTED);
		stdErrors.add(OIDCError.REQUEST_NOT_SUPPORTED);
		stdErrors.add(OIDCError.REQUEST_URI_NOT_SUPPORTED);
	}


	/**
	 * Gets the standard errors for an OpenID Connect authentication error
	 * response.
	 *
	 * @return The standard errors, as a read-only set.
	 */
	public static Set<ErrorObject> getStandardErrors() {
	
		return Collections.unmodifiableSet(stdErrors);
	}


	/**
	 * Creates a new OpenID Connect authentication error response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param error       The error. Should match one of the 
	 *                    {@link #getStandardErrors standard errors} for an 
	 *                    OpenID Connect authentication error response.
	 *                    Must not be {@code null}.
	 * @param rt          The response type, used to determine the redirect
	 *                    URI composition. If unknown {@code null}.
	 * @param state       The state, {@code null} if not requested.
	 */
	public AuthenticationErrorResponse(final URI redirectURI,
					   final ErrorObject error,
					   final ResponseType rt,
					   final State state) {
					  
		super(redirectURI, error, rt, state);
	}


	@Override
	public URI toURI()
		throws SerializeException {

		StringBuilder sb = new StringBuilder(getRedirectionURI().toString());

		if (getResponseType() == null ||
		    getResponseType().contains(ResponseType.Value.TOKEN) ||
		    getResponseType().contains(OIDCResponseTypeValue.ID_TOKEN)) {

			sb.append("#");
		} else {

			sb.append("?");
		}

		sb.append(URLUtils.serializeParameters(toParameters()));

		try {
			return new URI(sb.toString());

		} catch (URISyntaxException e) {

			throw new SerializeException("Couldn't serialize redirection URI: " + e.getMessage(), e);
		}
	}


	/**
	 * Parses an OpenID Connect authentication error response from the
	 * specified redirection URI and parameters.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param params      The response parameters to parse. Must not be 
	 *                    {@code null}.
	 *
	 * @return The OpenID Connect authentication error response.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        OpenID Connect authentication error response.
	 */
	public static AuthenticationErrorResponse parse(final URI redirectURI,
							final Map<String,String> params)
		throws ParseException {

		AuthorizationErrorResponse resp = AuthorizationErrorResponse.parse(redirectURI, params);

		return new AuthenticationErrorResponse(resp.getRedirectionURI(),
			                                  resp.getErrorObject(),
			                                  resp.getResponseType(),
			                                  resp.getState());
	}


	/**
	 * Parses an OpenID Connect authentication error response from the
	 * specified URI.
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://client.example.com/cb?
	 * error=invalid_request
	 * &amp;error_description=the%20request%20is%20not%20valid%20or%20malformed
	 * &amp;state=af0ifjsldkj
	 * </pre>
	 *
	 * @param uri The URI to parse. Can be absolute or relative. Must not 
	 *            be {@code null}.
	 *
	 * @return The OpenID Connect authentication error response.
	 *
	 * @throws ParseException If the URI couldn't be parsed to an OpenID
	 *                        Connect authentication error response.
	 */
	public static AuthenticationErrorResponse parse(final URI uri)
		throws ParseException {

		AuthorizationErrorResponse resp = AuthorizationErrorResponse.parse(uri);

		return new AuthenticationErrorResponse(resp.getRedirectionURI(),
			                                  resp.getErrorObject(),
			                                  resp.getResponseType(),
			                                  resp.getState());
	}


	/**
	 * Parses an OpenID Connect authentication error response from the
	 * specified HTTP response.
	 *
	 * <p>Example HTTP response:
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: https://client.example.com/cb?
	 * error=invalid_request
	 * &amp;error_description=the%20request%20is%20not%20valid%20or%20malformed
	 * &amp;state=af0ifjsldkj
	 * </pre>
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @return The OpenID Connect authentication error response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        OpenID Connect authentication error response.
	 */
	public static AuthenticationErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		AuthorizationErrorResponse resp = AuthorizationErrorResponse.parse(httpResponse);

		return new AuthenticationErrorResponse(resp.getRedirectionURI(),
			                                  resp.getErrorObject(),
			                                  resp.getResponseType(),
			                                  resp.getState());
	}
}
