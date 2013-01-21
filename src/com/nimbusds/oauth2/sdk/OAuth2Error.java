package com.nimbusds.oauth2.sdk;


import java.net.URL;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * OAuth 2.0 error. This class is immutable.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-20)
 */
@Immutable
public final class OAuth2Error extends Identifier {

	
	// Base OAuth 2.0 authorisation errors
	
	/**
	 * The request is missing a required parameter, includes an invalid 
	 * parameter value, or is otherwise malformed.
	 */
	public static final OAuth2Error INVALID_REQUEST = 
		new OAuth2Error("invalid_request", "Invalid request");
	
	
	/**
	 * The client is not authorised to request an authorisation code using 
	 * this method.
	 */
	public static final OAuth2Error UNAUTHORIZED_CLIENT =
		new OAuth2Error("unauthorized_client", "Unauthorized client");
	
	
	/**
	 * The resource owner or authorisation server denied the request.
	 */
	public static final OAuth2Error ACCESS_DENIED =
		new OAuth2Error("access_denied", "Access denied by resource owner or authorization server");
	
	
	/**
	 * The authorisation server does not support obtaining an authorisation 
	 * code using this method.
	 */
	public static final OAuth2Error UNSUPPORTED_RESPONSE_TYPE =
		new OAuth2Error("unsupported_response_type", "Unsupported response type");
	
	
	/**
	 * The requested scope is invalid, unknown, or malformed.
	 */
	public static final OAuth2Error INVALID_SCOPE =
		new OAuth2Error("invalid_scope", "Invalid, unknown or malformed scope");
	
	
	/**
	 * The authorisation server encountered an unexpected condition which 
	 * prevented it from fulfilling the request.
	 */
	public static final OAuth2Error SERVER_ERROR =
		new OAuth2Error("server_error", "Unexpected server error");
	
	
	/**
	 * The authorisation server is currently unable to handle the request 
	 * due to a temporary overloading or maintenance of the server.
	 */
	public static final OAuth2Error TEMPORARILY_UNAVAILABLE =
		new OAuth2Error("temporarily_unavailable", "The authorization server is temporarily unavailable");
	
	
	// Token, Base OAuth 2.0 authorisation errors, section 5.2
	
	/**
	 * Client authentication failed (e.g. unknown client, no client 
	 * authentication included, or unsupported authentication method).
	 */
	public static final OAuth2Error INVALID_CLIENT =
		new OAuth2Error("invalid_client", "Client authentication failed");
	
	
	/**
	 * The provided authorisation grant (e.g. authorisation code, resource 
	 * owner credentials) or refresh token is invalid, expired, revoked, 
	 * does not match the redirection URI used in the authorization request,
	 * or was issued to another client.
	 */
	public static final OAuth2Error INVALID_GRANT =
		new OAuth2Error("invalid_grant", "Invalid grant");
	
	
	/**
	 * The authorisation grant type is not supported by the authorisation 
	 * server.
	 */
	public static final OAuth2Error UNSUPPORTED_GRANT_TYPE =
		new OAuth2Error("unsupported_grant_type", "Unsupported grant type");
	
	
	// OAuth Bearer, section 3.1
	
	/**
	 * The access token provided is expired, revoked, malformed, or invalid
	 * for other reasons.  The resource should respond with the HTTP 401 
	 * (Unauthorized) status code.  The client may request a new access 
	 * token and retry the protected resource request.
	 */
	public static final OAuth2Error INVALID_TOKEN =
		new OAuth2Error("invalid_token", "Invalid access token");
	
	
	/**
	 * The request requires higher privileges than provided by the access 
	 * token.  The resource server should respond with the HTTP 403 
	 * (Forbidden) status code and may include the {@code scope} attribute 
	 * with the scope necessary to access the protected resource.
	 */
	public static final OAuth2Error INSUFFICIENT_SCOPE =
		new OAuth2Error("insufficient_scope", "Insufficient scope");
	
	
	/**
	 * Optional error description.
	 */
	private final String description;


	/**
	 * Optional URI of a web page that includes additional information 
	 * about the error.
	 */
	private final URL uri;


	/**
	 * Creates a new OAuth 2.0 error with the specified code value.
	 *
	 * @param value The error code value. Must not be {@code null} or
	 *              empty string.
	 */
	public OAuth2Error(final String value) {
	
		this(value, null, null);
	}
	
	
	/**
	 * Creates a new OAuth 2.0 error with the specified code value and 
	 * description.
	 *
	 * @param value       The error code value. Must not be {@code null} or
	 *                    empty string.
	 * @param description The error description, {@code null} if not
	 *                    specified.
	 */
	public OAuth2Error(final String value, final String description) {
	
		this(value, description, null);
	}


	/**
	 * Creates a new OAuth 2.0 error with the specified code value,
	 * description and page URI.
	 *
	 * @param value       The error code value. Must not be {@code null} or
	 *                    empty string.
	 * @param description The error description, {@code null} if not
	 *                    specified.
	 * @param uri         The error page URI, {@code null} if not
	 *                    specified.
	 */
	public OAuth2Error(final String value, final String description, final URL uri) {
	
		super(value);
		this.description = description;
		this.uri = uri;
	}
	
	
	/**
	 * Gets the error description.
	 *
	 * @return The error description, {@code null} if not specified.
	 */
	public String getDescription() {
	
		return description;
	}


	/**
	 * Gets the error page URI.
	 *
	 * @return The error page URI, {@code null} if not specified.
	 */
	public URL getURI() {

		return uri;
	}


	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof OAuth2Error && 
		       this.toString().equals(object.toString());
	}
}
