package com.nimbusds.openid.connect.sdk;


import java.net.URL;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * OpenID Connect authorisation error response. This class is immutable.
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
 *             <li>{@link OIDCError#SESSION_SELECTION_REQUIRED}
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
 *     <li>OpenID Connect Messages 1.0, section 2.1.3.
 *     <li>OpenID Connect Standard 1.0, section 2.3.5.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public class OIDCAuthorizationErrorResponse 
	extends AuthorizationErrorResponse
	implements OIDCAuthorizationResponse { 


	/**
	 * The standard errors for an OpenID Connect Authorisation error 
	 * response.
	 */
	private static Set<ErrorObject> stdErrors = new HashSet<ErrorObject>();
	
	
	static {
		stdErrors.addAll(AuthorizationErrorResponse.getStandardErrors());

		stdErrors.add(OIDCError.INTERACTION_REQUIRED);
		stdErrors.add(OIDCError.LOGIN_REQUIRED);
		stdErrors.add(OIDCError.SESSION_SELECTION_REQUIRED);
		stdErrors.add(OIDCError.CONSENT_REQUIRED);
		stdErrors.add(OIDCError.INVALID_REQUEST_URI);
		stdErrors.add(OIDCError.INVALID_REQUEST_OBJECT);
		stdErrors.add(OIDCError.REGISTRATION_NOT_SUPPORTED);
		stdErrors.add(OIDCError.REQUEST_NOT_SUPPORTED);
		stdErrors.add(OIDCError.REQUEST_URI_NOT_SUPPORTED);
	}


	/**
	 * Gets the standard errors for an OpenID Connect Authorisation error 
	 * response.
	 *
	 * @return The standard errors, as a read-only set.
	 */
	public static Set<ErrorObject> getStandardErrors() {
	
		return Collections.unmodifiableSet(stdErrors);
	}


	/**
	 * Creates a new OpenID Connect authorisation error response.
	 *
	 * @param redirectURI The base redirect URI. Must not be {@code null}.
	 * @param error       The error. Should match one of the 
	 *                    {@link #getStandardErrors standard errors} for an 
	 *                    OpenID Connect authorisation error response. Must 
	 *                    not be {@code null}.
	 * @param rt          The response type, used to determine the redirect
	 *                    URI composition. If unknown {@code null}.
	 * @param state       The state, {@code null} if not requested.
	 */
	public OIDCAuthorizationErrorResponse(final URL redirectURI,
	                                      final ErrorObject error,
					      final ResponseType rt,
					      final State state) {
					  
		super(redirectURI, error, rt, state);
	}


	/**
	 * Parses an OpenID Connect authorisation error response from the 
	 * specified redirect URI and parameters.
	 *
	 * @param redirectURI The base redirect URI. Must not be {@code null}.
	 * @param params      The response parameters to parse. Must not be 
	 *                    {@code null}.
	 *
	 * @return The OpenID Connect authorisation error response.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        OpenID Connect authorisation error response.
	 */
	public static OIDCAuthorizationErrorResponse parse(final URL redirectURI, 
		                                           final Map<String,String> params)
		throws ParseException {

		AuthorizationErrorResponse resp = AuthorizationErrorResponse.parse(redirectURI, params);

		return new OIDCAuthorizationErrorResponse(resp.getRedirectionURI(),
			                                  resp.getErrorObject(),
			                                  resp.getResponseType(),
			                                  resp.getState());
	}


	/**
	 * Parses an OpenID Connect authorisation error response from the 
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
	 * @return The OpenID Connect authorisation error response.
	 *
	 * @throws ParseException If the URI couldn't be parsed to an OpenID
	 *                        Connect authorisation error response.
	 */
	public static OIDCAuthorizationErrorResponse parse(final URL uri)
		throws ParseException {

		AuthorizationErrorResponse resp = AuthorizationErrorResponse.parse(uri);

		return new OIDCAuthorizationErrorResponse(resp.getRedirectionURI(),
			                                  resp.getErrorObject(),
			                                  resp.getResponseType(),
			                                  resp.getState());
	}


	/**
	 * Parses an OpenID Connect authorisation error response from the 
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
	 * @return The OpenID Connect authorisation error response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        OpenID Connect authorisation error response.
	 */
	public static OIDCAuthorizationErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		AuthorizationErrorResponse resp = AuthorizationErrorResponse.parse(httpResponse);

		return new OIDCAuthorizationErrorResponse(resp.getRedirectionURI(),
			                                  resp.getErrorObject(),
			                                  resp.getResponseType(),
			                                  resp.getState());
	}
}
