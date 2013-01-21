package com.nimbusds.openid.connect.sdk;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.OAuth2Error;


/**
 * OpenID Connect specific errors. Extend the standard 
 * {@link com.nimbusds.oauth2.sdk.OAuth2Error OAuth 2.0 errors}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-21)
 */
@Immutable
public final class OIDCError {

	
	// Authorisation
        
	/**
	 * The {@code redirect_uri} in the {@link OIDCAuthorizationRequest} 
	 * dost not match any of the client's pre-registered
	 * {@code redirect_uri}s. 
	 */
	public static final OAuth2Error INVALID_REDIRECT_URI =
		new OAuth2Error("invalid_redirect_uri", "Invalid redirect URI");


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
		new OAuth2Error("login_required", "Login required");


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
		new OAuth2Error("session_selection_required", "Session selection required");


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
		new OAuth2Error("invalid_request_uri", "Invalid request URI");


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
		new OAuth2Error("interaction_required", "User interaction required");


	/**
	 * The request parameter contains an invalid OpenID Request Object.
	 */
	public static final OAuth2Error	INVALID_OPENID_REQUEST_OBJECT =
		new OAuth2Error("invalid_openid_request_object", "Invalid OpenID request object");


	/**
	 * Prevents public instantiation.
	 */
	private OIDCError() { }
}
