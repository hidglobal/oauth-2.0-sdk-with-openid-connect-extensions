package com.nimbusds.openid.connect.sdk;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.BearerTokenError;
import com.nimbusds.oauth2.sdk.OAuth2Error;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * OpenID Connect specific errors. Extend the standard 
 * {@link com.nimbusds.oauth2.sdk.OAuth2Error OAuth 2.0 errors}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-28)
 */
@Immutable
public final class OIDCError {

	
	// Authorisation

	/**
	 * The authorisation server requires end-user authentication. This 
	 * error may be returned when the prompt parameter in the 
	 * {@link OIDCAuthorizationRequest} is set to {@link Prompt.Type#NONE} 
	 * to request that the authorisation server should not display any user 
	 * interfaces to the end-user, but the {@link OIDCAuthorizationRequest} 
	 * cannot be completed without displaying a user interface for user 
	 * authentication.
	 */
	public static final OAuth2Error LOGIN_REQUIRED =
		new OAuth2Error("login_required", "Login required", 
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
	public static final OAuth2Error SESSION_SELECTION_REQUIRED =
		new OAuth2Error("session_selection_required", "Session selection required",
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
	public static final OAuth2Error	CONSENT_REQUIRED =
		new OAuth2Error("consent_required", "Consent required");


	/**
	 * The {@code request_uri} in the {@link OIDCAuthorizationRequest} 
	 * returns an error or invalid data.
	 */
	public static final OAuth2Error INVALID_REQUEST_URI =
		new OAuth2Error("invalid_request_uri", "Invalid request URI",
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
	public static final OAuth2Error INTERACTION_REQUIRED =
		new OAuth2Error("interaction_required", "User interaction required",
			        HTTPResponse.SC_FOUND);


	/**
	 * The request parameter contains an invalid OpenID Request Object.
	 */
	public static final OAuth2Error	INVALID_OPENID_REQUEST_OBJECT =
		new OAuth2Error("invalid_openid_request_object", "Invalid OpenID request object",
			        HTTPResponse.SC_FOUND);


	// UserInfo

	/**
	 * The requested UserInfo schema is invalid or unsupported.
	 */
	public static final BearerTokenError INVALID_SCHEMA =
		new BearerTokenError("invalid_schema", "The requested schema is invalid or unsupported",
			             HTTPResponse.SC_BAD_REQUEST);


	// Client registration
	
	/**
	 * Client registration: The value of the registration {@code operation}
	 * is invalid or not supported.
	 */
	public static final OAuth2Error INVALID_OPERATION =
		new OAuth2Error("invalid_operation", "Invalid or unsupported client registration operation");
	
	
	/**
	 * Client registration: The value of {@code client_id} is invalid. 
	 */
	public static final OAuth2Error	INVALID_CLIENT_ID =
		new OAuth2Error("invalid_client_id", "Invalid client identifier");
	
	
	/**
	 * Client registration: The {@code client_secret} provided for a 
	 * {@code client_update} or {@code secret_rotate} is not valid for the 
	 * provided {@code client_id}.
	 */
	public static final OAuth2Error INVALID_CLIENT_SECRET =
		new OAuth2Error("invalid_client_secret", "Invalid client secret");


	/**
	 * Client registration: The value of one or more {@code redirect_uris} 
	 * is invalid. 
	 */
	public static final OAuth2Error INVALID_REDIRECT_URI =
		new OAuth2Error("invalid_redirect_uri", "Invalid redirection URI(s)");
	
	
	/**
	 * Client registration: The value of one of the configuration 
	 * parameters is invalid.
	 */
	public static final OAuth2Error	INVALID_CONFIGURATION_PARAMETER =
		new OAuth2Error("invalid_configuration_parameter", "Invalid configuration parameter");

	
	/**
	 * Prevents public instantiation.
	 */
	private OIDCError() { }
}
