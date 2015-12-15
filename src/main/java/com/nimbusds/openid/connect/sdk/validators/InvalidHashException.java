package com.nimbusds.openid.connect.sdk.validators;


/**
 * Invalid access token / code hash exception.
 */
public class InvalidHashException extends Exception {


	/**
	 * Invalid access token hash exception.
	 */
	public static final InvalidHashException INVALID_ACCESS_T0KEN_HASH_EXCEPTION
		= new InvalidHashException("Invalid access token hash (at_hash)");
	

	/**
	 * Invalid authorisation code hash exception.
	 */
	public static final InvalidHashException INVALID_CODE_HASH_EXCEPTION
		= new InvalidHashException("Invalid authorization code hash (c_hash)");


	/**
	 * Creates a new invalid hash exception.
	 *
	 * @param message The exception message.
	 */
	private InvalidHashException(String message) {
		super(message);
	}
}
