package com.nimbusds.openid.connect.messages;


/**
 * Enumeration of the {@link ClientRegistrationRequest client registration} 
 * types.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-03-13)
 */
public enum ClientRegistrationType {

	
	/**
	 * New registration.
	 */
	CLIENT_ASSOCIATE,
	
	
	/**
	 * Updating parameters for an existing 
	 * {@link com.nimbusds.openid.connect.claims.ClientID client}.
	 */
	CLIENT_UPDATE;
	
	
	/**
	 * Returns the canonical string representation of this client 
	 * registration type.
	 *
	 * @return The string representation of this client registration type.
	 */
	public String toString() {
	
		return super.toString().toLowerCase();
	}
}
