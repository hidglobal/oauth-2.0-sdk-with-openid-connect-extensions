package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * OpenID Connect specific errors.
 *
 * @author Vladimir Dzhuvinov
 */
public final class OIDCError {

	
	// Authorisation endpoint
	
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
	 * The {@code request} parameter in the {@link OIDCAuthorizationRequest}
	 * contains an invalid OpenID Connect request object.
	 */
	public static final ErrorObject	INVALID_REQUEST_OBJECT =
		new ErrorObject("invalid_request_object", "Invalid OpenID Connect request object",
			        HTTPResponse.SC_FOUND);

	
	/**
	 * The {@code registration} parameter in the 
	 * {@link OIDCAuthorizationRequest} is not supported. Applies only to
	 * self-issued OpenID providers.
	 */
	public static final ErrorObject REGISTRATION_NOT_SUPPORTED =
		new ErrorObject("registration_not_supported", "Registration parameter not supported",
		                HTTPResponse.SC_FOUND);
	
	
	/**
	 * The {@code request} parameter in the 
	 * {@link OIDCAuthorizationRequest} is not supported.
	 */
	public static final ErrorObject REQUEST_NOT_SUPPORTED =
		new ErrorObject("request_not_supported", "Request parameter not supported",
		                HTTPResponse.SC_FOUND);
	
	
	/**
	 * The {@code request_uri} parameter in the 
	 * {@link OIDCAuthorizationRequest} is not supported.
	 */
	public static final ErrorObject REQUEST_URI_NOT_SUPPORTED =
		new ErrorObject("request_uri_not_supported", "Request URI parameter not supported",
		                HTTPResponse.SC_FOUND);

	
	/**
	 * Prevents public instantiation.
	 */
	private OIDCError() { }
}
