package com.nimbusds.oauth2.sdk.client;


import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * OAuth 2.0 client registration errors.
 * 
 * @author Vladimir Dzhuvinov
 */
public final class RegistrationError {
	
	
	/**
	 * Client registration: The value of one or more {@code redirect_uris} 
	 * is invalid. 
	 */
	public static final ErrorObject INVALID_REDIRECT_URI =
		new ErrorObject("invalid_redirect_uri", "Invalid redirect URI(s)",
			        HTTPResponse.SC_BAD_REQUEST);
	
	
	/**
	 * Client registration: The value of one of the client meta data fields
	 * is invalid and the server has rejected this request. Note that an 
	 * authorisation server may choose to substitute a valid value for any 
	 * requested parameter of a client's meta data. 
	 */
	public static final ErrorObject	INVALID_CLIENT_METADATA =
		new ErrorObject("invalid_client_metadata", "Invalid client metedata field",
			        HTTPResponse.SC_BAD_REQUEST);
	
	
	/**
	 * Prevents public instantiation.
	 */
	private RegistrationError() { }
	
}
