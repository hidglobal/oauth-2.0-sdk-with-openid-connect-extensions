package com.nimbusds.oauth2.sdk;


/**
 * OAuth 2.0 authorisation and token endpoint errors.
 *
 * @author Vladimir Dzhuvinov
 */
public final class OAuth2Error {


	// Base OAuth 2.0 authorisation errors
	
	/**
	 * The request is missing a required parameter, includes an invalid 
	 * parameter code, or is otherwise malformed.
	 */
	public static final ErrorObject INVALID_REQUEST = 
		new ErrorObject("invalid_request", "Invalid request");
	
	
	/**
	 * The client is not authorised to request an authorisation code using 
	 * this method.
	 */
	public static final ErrorObject UNAUTHORIZED_CLIENT =
		new ErrorObject("unauthorized_client", "Unauthorized client");
	
	
	/**
	 * The resource owner or authorisation server denied the request.
	 */
	public static final ErrorObject ACCESS_DENIED =
		new ErrorObject("access_denied", "Access denied by resource owner or authorization server");
	
	
	/**
	 * The authorisation server does not support obtaining an authorisation 
	 * code using this method.
	 */
	public static final ErrorObject UNSUPPORTED_RESPONSE_TYPE =
		new ErrorObject("unsupported_response_type", "Unsupported response type");
	
	
	/**
	 * The requested scope is invalid, unknown, or malformed.
	 */
	public static final ErrorObject INVALID_SCOPE =
		new ErrorObject("invalid_scope", "Invalid, unknown or malformed scope");
	
	
	/**
	 * The authorisation server encountered an unexpected condition which 
	 * prevented it from fulfilling the request.
	 */
	public static final ErrorObject SERVER_ERROR =
		new ErrorObject("server_error", "Unexpected server error");
	
	
	/**
	 * The authorisation server is currently unable to handle the request 
	 * due to a temporary overloading or maintenance of the server.
	 */
	public static final ErrorObject TEMPORARILY_UNAVAILABLE =
		new ErrorObject("temporarily_unavailable", "The authorization server is temporarily unavailable");
	
	
	// Token, Base OAuth 2.0 authorisation errors, section 5.2
	
	/**
	 * Client authentication failed (e.g. unknown client, no client 
	 * authentication included, or unsupported authentication method).
	 */
	public static final ErrorObject INVALID_CLIENT =
		new ErrorObject("invalid_client", "Client authentication failed");
	
	
	/**
	 * The provided authorisation grant (e.g. authorisation code, resource 
	 * owner credentials) or refresh token is invalid, expired, revoked, 
	 * does not match the redirection URI used in the authorization request,
	 * or was issued to another client.
	 */
	public static final ErrorObject INVALID_GRANT =
		new ErrorObject("invalid_grant", "Invalid grant");
	
	
	/**
	 * The authorisation grant type is not supported by the authorisation 
	 * server.
	 */
	public static final ErrorObject UNSUPPORTED_GRANT_TYPE =
		new ErrorObject("unsupported_grant_type", "Unsupported grant type");

	
	/**
	 * Prevents public instantiation.
	 */
	private OAuth2Error() { }
}