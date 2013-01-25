package com.nimbusds.openid.connect.sdk.relyingparty;


/**
 * Enumeration of OpenID Connect client application types.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-12-25)
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
	 * Gets the default application type.
	 *
	 * @return {@link #WEB}
	 */
	public static ApplicationType getDefault() {

		return WEB;
	}


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