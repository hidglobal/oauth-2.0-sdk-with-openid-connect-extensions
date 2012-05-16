package com.nimbusds.openid.connect.messages;


/**
 * Enumeration of the application types in the context of OpenID Connect.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-03-13)
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
	 * Returns the canonical string representation of this application 
	 * type.
	 *
	 * @return The string representation of this application type.
	 */
	public String toString() {
	
		return super.toString().toLowerCase();
	}
}
