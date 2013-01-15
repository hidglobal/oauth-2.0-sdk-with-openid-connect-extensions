package com.nimbusds.oauth2.sdk;


import java.net.URL;

import net.jcip.annotations.Immutable;


/**
 * OAuth 2.0 error. This class is immutable.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-15)
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

	
	// Client registration
	
	/**
	 * The value of {@code type} is invalid or not supported.
	 */
	public static final OAuth2Error INVALID_TYPE =
		new OAuth2Error("invalid_type", "Invalid or unsupported client registration type");
	
	
	/**
	 * The value of {@code client_id} is invalid. 
	 */
	public static final OAuth2Error INVALID_CLIENT_ID =
		new OAuth2Error("invalid_client_id", "Invalid client identifier");
	
	
	/**
	 * The {@code client_secret} provided for a {@code client_update} or
	 * {@code secret_rotate} is not valid for the provided 
	 * {@code client_id}.
	 */
	public static final OAuth2Error INVALID_CLIENT_SECRET =
		new OAuth2Error("invalid_client_secret", "Invalid client secret");
	
	
	/**
	 * The value of one of the configuration parameters is invalid.
	 */
	public static final OAuth2Error INVALID_CONFIGURATION_PARAMETER =
		new OAuth2Error("invalid_configuration_parameter", "Invalid configuration parameter");
	
	
	// Authorisation
	
	/**
	 * The {@code redirect_uri} in the {@link AuthorizationRequest} does 
	 * not match any of the client's pre-registered {@code redirect_uri}s. 
	 */
	public static final OAuth2Error INVALID_REDIRECT_URI =
		new OAuth2Error("invalid_redirect_uri", "Invalid redirect URI");
	
	
	/**
	 * The authorisation server requires end-user authentication. This error 
	 * may be returned when the prompt parameter in the 
	 * {@link AuthorizationRequest} is set to {@link Prompt.Type#NONE} to 
	 * request that the authorisation server should not display any user 
	 * interfaces to the end-user, but the {@link AuthorizationRequest} 
	 * cannot be completed without displaying a user interface for user 
	 * authentication.
	 */
	public static final OAuth2Error LOGIN_REQUIRED =
		new OAuth2Error("LOGIN_REQUIRED", "Login required");
	
	
	/**
	 * The end-user is required to select a session at the authorisation 
	 * server. The end-user may be authenticated at the authorisation server
	 * with different associated accounts, but the end-user did not select a 
	 * session. This error may be returned when the prompt parameter in the 
	 * {@link AuthorizationRequest} is set to {@link Prompt.Type#NONE} to 
	 * request that the authorisation server should not display any user 
	 * interfaces to the end-user, but the {@link AuthorizationRequest} 
	 * cannot be completed without displaying a user interface to prompt for
	 * a session to use.
	 */
	public static final OAuth2Error SESSION_SELECTION_REQUIRED =
		new OAuth2Error("SESSION_SELECTION_REQUIRED", "Session selection required");
	
	
	/**
	 * The authorisation server requires end-user consent. This error may be
	 * returned when the prompt parameter in the {@link AuthorizationRequest}
	 * is set to {@link Prompt.Type#NONE} to request that the authorisation 
	 * server should not display any user interfaces to the end-user, but the 
	 * {@link AuthorizationRequest} cannot be completed without displaying a 
	 * user interface for end-user consent.
	 */
	public static final OAuth2Error CONSENT_REQUIRED =
		new OAuth2Error("CONSENT_REQUIRED", "Consent required");
	
	
	/**
	 * The {@code request_uri} in the {@link AuthorizationRequest} returns 
	 * an error or invalid data.
	 */
	public static final OAuth2Error INVALID_REQUEST_URI =
		new OAuth2Error("INVALID_REQUEST_URI", "Invalid request URI");
	

	/**
	 * The authorisation server requires end-user interaction of some form 
	 * to proceed. This error may be returned when the {@link Prompt} 
	 * parameter in the {@link AuthorizationRequest} is set to 
	 * {@link Prompt.Type#NONE none} to request that the authorisation 
	 * server should not display any user interfaces to the end-user, but 
	 * the {@link AuthorizationRequest} cannot be completed without 
	 * displaying a user interface for end-user interaction.
	 */
	public static final OAuth2Error INTERACTION_REQUIRED =
		new OAuth2Error("INTERACTION_REQUIRED", "User interaction required");
	
	
	/**
	 * The request parameter contains an invalid OpenID Request Object.
	 */
	public static final OAuth2Error INVALID_OPENID_REQUEST_OBJECT =
		new OAuth2Error("INVALID_OPENID_REQUEST_OBJECT", "Invalid OpenID request object");
	
	
	// Token, Base OAuth 2.0 authorisation errors, section 5.2
	
	/**
	 * Client authentication failed (e.g. unknown client, no client 
	 * authentication included, or unsupported authentication method).
	 */
	public static final OAuth2Error INVALID_CLIENT =
		new OAuth2Error("INVALID_CLIENT", "Client authentication failed");
	
	
	/**
	 * The provided authorisation grant (e.g. authorisation code, resource 
	 * owner credentials) or refresh token is invalid, expired, revoked, 
	 * does not match the redirection URI used in the authorization request,
	 * or was issued to another client.
	 */
	public static final OAuth2Error INVALID_GRANT =
		new OAuth2Error("INVALID_GRANT", "Invalid grant");
	
	
	/**
	 * The authorisation grant type is not supported by the authorisation 
	 * server.
	 */
	public static final OAuth2Error UNSUPPORTED_GRANT_TYPE =
		new OAuth2Error("UNSUPPORTED_GRANT_TYPE", "Unsupported grant type");
	
	
	// OAuth Bearer, seciton 3.1
	
	/**
	 * The access token provided is expired, revoked, malformed, or invalid
	 * for other reasons.  The resource should respond with the HTTP 401 
	 * (Unauthorized) status code.  The client may request a new access 
	 * token and retry the protected resource request.
	 */
	public static final OAuth2Error INVALID_TOKEN =
		new OAuth2Error("INVALID_TOKEN", "Invalid access token");
	
	
	/**
	 * The request requires higher privileges than provided by the access 
	 * token.  The resource server should respond with the HTTP 403 
	 * (Forbidden) status code and may include the {@code scope} attribute 
	 * with the scope necessary to access the protected resource.
	 */
	public static final OAuth2Error INSUFFICIENT_SCOPE =
		new OAuth2Error("INSUFFICIENT_SCOPE", "Insufficient scope");
	
	
	// UserInfo
	
	/**
	 * The requested schema is invalid or unsupported.
	 */
	public static final OAuth2Error INVALID_SCHEMA =
		new OAuth2Error("INVALID_SCHEMA", "Invalid or unsupported schema");
	
	
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
