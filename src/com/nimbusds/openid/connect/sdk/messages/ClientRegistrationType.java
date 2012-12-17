package com.nimbusds.openid.connect.sdk.messages;


/**
 * Enumeration of the {@link ClientRegistrationRequest client registration} 
 * types.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-12-17)
 */
public enum ClientRegistrationType {

	
	/**
	 * New registration.
	 */
	CLIENT_ASSOCIATE,
	
	
	/**
	 * Update for a registered client}.
	 */
	CLIENT_UPDATE;
	
	
	/**
	 * Returns the string identifier of this client registration type.
	 *
	 * @return The string identifier.
	 */
	public String toString() {
	
		return super.toString().toLowerCase();
	}
}
