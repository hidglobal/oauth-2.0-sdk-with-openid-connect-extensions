package com.nimbusds.openid.connect.sdk.relyingparty;


/**
 * Enumeration of OpenID Connect client application types.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-05)
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