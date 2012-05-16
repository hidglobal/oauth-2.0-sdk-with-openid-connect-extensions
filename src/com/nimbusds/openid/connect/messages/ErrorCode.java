package com.nimbusds.openid.connect.messages;



/**
 * Enumeration of OpenID Connect error codes.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-02)
 */
public enum ErrorCode {

	
	// Base OAuth 2.0 authorisation errors, section 4.1.2.1
	
	/**
	 * The request is missing a required parameter, includes an invalid 
	 * parameter value, or is otherwise malformed.
	 */
	INVALID_REQUEST("Invalid request"),
	
	
	/**
	 * The client is not authorised to request an authorisation code using 
	 * this method.
	 */
	UNAUTHORIZED_CLIENT("Unauthorized client"),
	
	
	/**
	 * The resource owner or authorisation server denied the request.
	 */
	ACCESS_DENIED("Access denied by resource owner or authorization server"),
	
	
	/**
	 * The authorisation server does not support obtaining an authorisation 
	 * code using this method.
	 */
	UNSUPPORTED_RESPONSE_TYPE("Unsupported response type"),
	
	
	/**
	 * The requested scope is invalid, unknown, or malformed.
	 */
	INVALID_SCOPE("Invalid, unknown or malformed scope"),
	
	
	/**
	 * The authorisation server encountered an unexpected condition which 
	 * prevented it from fulfilling the request.
	 */
	SERVER_ERROR("Unexptected server error"),
	
	
	/**
	 * The authorisation server is currently unable to handle the request 
	 * due to a temporary overloading or maintenance of the server.
	 */
	TEMPORARILY_UNAVAILABLE("The authorization server is temporarily unavailable"),
	
	// Client registration
	
	/**
	 * The value of {@code type} is invalid or not supported.
	 */
	INVALID_TYPE("Invalid or unsupported type value"),
	
	
	/**
	 * The value of {@code client_id} is invalid. 
	 */
	INVALID_CLIENT_ID("Invalid client identifier"),
	
	
	/**
	 * The {@code client_secret} provided for a {@code client_update} is not
	 * valid for the provided {@code client_id}.
	 */
	INVALID_CLIENT_SECRET("Invalid client secret"),
	
	
	/**
	 * The value of one of the configuration parameters is invalid.
	 */
	INVALID_CONFIGURATION_PARAMETER("Invalid configuration parameter"),
	
	
	// Authorisation
	
	/**
	 * The {@code redirect_uri} in the {@link AuthorizationRequest} does not
	 * match any of the client's pre-registered {@code redirect_uri}s. 
	 */
	INVALID_REDIRECT_URI("Invalid redirect URI"),
	
	
	/**
	 * The authorisation server requires end-user authentication. This error 
	 * may be returned when the prompt parameter in the 
	 * {@link AuthorizationRequest} is set to {@link Prompt.Type#NONE} to 
	 * request that the authorisation server should not display any user 
	 * interfaces to the end-user, but the {@link AuthorizationRequest} 
	 * cannot be completed without displaying a user interface for user 
	 * authentication.
	 */
	LOGIN_REQUIRED("Login required"),
	
	
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
	SESSION_SELECTION_REQUIRED("Session selection required"),
	
	
	/**
	 * The authorisation server requires end-user consent. This error may be
	 * returned when the prompt parameter in the {@link AuthorizationRequest}
	 * is set to {@link Prompt.Type#NONE} to request that the authorisation 
	 * server should not display any user interfaces to the end-user, but the 
	 * {@link AuthorizationRequest} cannot be completed without displaying a 
	 * user interface for end-user consent.
	 */
	CONSENT_REQUIRED("Consent required"),
	
	
	/**
	 * The {@code request_uri} in the {@link AuthorizationRequest} returns 
	 * an error or invalid data.
	 */
	INVALID_REQUEST_URI("Invalid request URI"),
	

	/**
	 * The authorisation server requires end-user interaction of some form 
	 * to proceed. This error may be returned when the {@link Prompt} 
	 * parameter in the {@link AuthorizationRequest} is set to 
	 * {@link Prompt.Type#NONE none} to request that the authorisation 
	 * server should not display any user interfaces to the end-user, but 
	 * the {@link AuthorizationRequest} cannot be completed without 
	 * displaying a user interface for end-user interaction.
	 */
	INTERACTION_REQUIRED("User interaction required"),
	
	
	/**
	 * The request parameter contains an invalid OpenID Request Object.
	 */
	INVALID_OPENID_REQUEST_OBJECT("Invalid OpenID request object"),
	
	
	// Token, Base OAuth 2.0 authorisation errors, section 5.2
	
	/**
	 * Client authentication failed (e.g. unknown client, no client 
	 * authentication included, or unsupported authentication method).
	 */
	INVALID_CLIENT("Client authentication failed"),
	
	
	/**
	 * The provided authorisation grant (e.g. authorisation code, resource 
	 * owner credentials) or refresh token is invalid, expired, revoked, 
	 * does not match the redirection URI used in the authorization request,
	 * or was issued to another client.
	 */
	INVALID_GRANT("Invalid grant"),
	
	
	/**
	 * The authorisation grant type is not supported by the authorisation 
	 * server.
	 */
	UNSUPPORTED_GRANT_TYPE("Unsupported grant type"),
	
	
	
	// Check ID, OAuth Bearer, seciton 3.1
	
	/**
	 * The access token provided is expired, revoked, malformed, or invalid
	 * for other reasons.  The resource should respond with the HTTP 401 
	 * (Unauthorized) status code.  The client may request a new access 
	 * token and retry the protected resource request.
	 */
	INVALID_TOKEN("Invalid access token"),
	
	
	/**
	 * The request requires higher privileges than provided by the access 
	 * token.  The resource server should respond with the HTTP 403 
	 * (Forbidden) status code and may include the {@code scope} attribute 
	 * with the scope necessary to access the protected resource.
	 */
	INSUFFICIENT_SCOPE("Insufficient scope"),
	
	
	// UserInfo
	
	/**
	 * The requested schema is invalid or unsupported.
	 */
	INVALID_SCHEMA("Invalid or unsupported schema");
	
	
	/**
	 * The error description.
	 */
	private String description;
	
	
	/**
	 * Creates a new error with the specified description. The code is the
	 * constant name converted to lower case.
	 *
	 * @param description The error description.
	 */
	private ErrorCode (final String description) {
	
		this.description = description;
	}


	/**
	 * Gets the error code. This is the constant name converted to lower
	 * case.
	 *
	 * @return The error code.
	 */
	public String getCode() {
	
		return super.toString().toLowerCase();
	}
	
	
	/**
	 * Gets the error description.
	 *
	 * @return The error description.
	 */
	public String getDescription() {
	
		return description;
	}
}
