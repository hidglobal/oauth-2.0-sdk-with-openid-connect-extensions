package com.nimbusds.openid.connect.sdk.messages;


/**
 * Enumeration of the application types in the context of OpenID Connect.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-09)
 */
public enum ApplicationType {

	
	/**
	 * Native application.
	 */
	NATIVE,
	
	
	/**
	 * Web application.
	 */
	WEB;
	
	
	/**
	 * Returns the string identifier of this application type.
	 *
	 * @return The string identifier.
	 */
	@Override
	public String toString() {
	
		return super.toString().toLowerCase();
	}
}
