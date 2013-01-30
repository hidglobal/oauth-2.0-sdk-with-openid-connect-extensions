package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.ErrorObject;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import com.nimbusds.oauth2.sdk.token.BearerTokenError;


/**
 * OpenID Connect specific errors.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-30)
 */
public final class OIDCError {

	
	// Authorisation endpoint

	/**
	 * The authorisation server requires end-user authentication. This 
	 * error may be returned when the prompt parameter in the 
	 * {@link OIDCAuthorizationRequest} is set to {@link Prompt.Type#NONE} 
	 * to request that the authorisation server should not display any user 
	 * interfaces to the end-user, but the {@link OIDCAuthorizationRequest} 
	 * cannot be completed without displaying a user interface for user 
	 * authentication.
	 */
	public static final ErrorObject LOGIN_REQUIRED =
		new ErrorObject("login_required", "Login required", 
			        HTTPResponse.SC_FOUND);


	/**
	 * The end-user is required to select a session at the authorisation 
	 * server. The end-user may be authenticated at the authorisation 
	 * server with different associated accounts, but the end-user did not 
	 * select a session. This error may be returned when the prompt 
	 * parameter in the {@link OIDCAuthorizationRequest} is set to 
	 * {@link Prompt.Type#NONE} to request that the authorisation server 
	 * should not display any user interfaces to the end-user, but the 
	 * {@link OIDCAuthorizationRequest} cannot be completed without 
	 * displaying a user interface to prompt for a session to use.
	 */
	public static final ErrorObject SESSION_SELECTION_REQUIRED =
		new ErrorObject("session_selection_required", "Session selection required",
			        HTTPResponse.SC_FOUND);


	/**
	 * The authorisation server requires end-user consent. This error may 
	 * be returned when the prompt parameter in the 
	 * {@link OIDCAuthorizationRequest} is set to {@link Prompt.Type#NONE}
	 * to request that the authorisation server should not display any 
	 * user interfaces to the end-user, but the 
	 * {@link OIDCAuthorizationRequest} cannot be completed without 
	 * displaying a user interface for end-user consent.
	 */
	public static final ErrorObject	CONSENT_REQUIRED =
		new ErrorObject("consent_required", "Consent required");


	/**
	 * The {@code request_uri} in the {@link OIDCAuthorizationRequest} 
	 * returns an error or invalid data.
	 */
	public static final ErrorObject INVALID_REQUEST_URI =
		new ErrorObject("invalid_request_uri", "Invalid request URI",
			        HTTPResponse.SC_FOUND);


	/**
	 * The authorisation server requires end-user interaction of some form 
	 * to proceed. This error may be returned when the {@link Prompt} 
	 * parameter in the {@link OIDCAuthorizationRequest} is set to 
	 * {@link Prompt.Type#NONE none} to request that the authorisation 
	 * server should not display any user interfaces to the end-user, but 
	 * the {@link OIDCAuthorizationRequest} cannot be completed without 
	 * displaying a user interface for end-user interaction.
	 */
	public static final ErrorObject INTERACTION_REQUIRED =
		new ErrorObject("interaction_required", "User interaction required",
			        HTTPResponse.SC_FOUND);


	/**
	 * The request parameter contains an invalid OpenID Request Object.
	 */
	public static final ErrorObject	INVALID_OPENID_REQUEST_OBJECT =
		new ErrorObject("invalid_openid_request_object", "Invalid OpenID request object",
			        HTTPResponse.SC_FOUND);


	// UserInfo endpoint

	/**
	 * The requested UserInfo schema is invalid or unsupported.
	 */
	public static final BearerTokenError INVALID_SCHEMA =
		new BearerTokenError("invalid_schema", "The requested schema is invalid or unsupported",
			             HTTPResponse.SC_BAD_REQUEST);


	// Client registration endpoint
	
	/**
	 * Client registration: The value of the registration {@code operation}
	 * is invalid or not supported.
	 */
	public static final ErrorObject INVALID_OPERATION =
		new ErrorObject("invalid_operation", "Invalid or unsupported client registration operation",
			        HTTPResponse.SC_BAD_REQUEST);
	
	
	/**
	 * Client registration: The value of one or more {@code redirect_uris} 
	 * is invalid. 
	 */
	public static final ErrorObject INVALID_REDIRECT_URI =
		new ErrorObject("invalid_redirect_uri", "Invalid redirect URI(s)",
			        HTTPResponse.SC_BAD_REQUEST);
	
	
	/**
	 * Client registration: The value of one of the configuration 
	 * parameters is invalid.
	 */
	public static final ErrorObject	INVALID_CONFIGURATION_PARAMETER =
		new ErrorObject("invalid_configuration_parameter", "Invalid configuration parameter",
			        HTTPResponse.SC_BAD_REQUEST);

	
	/**
	 * Prevents public instantiation.
	 */
	private OIDCError() { }
}
