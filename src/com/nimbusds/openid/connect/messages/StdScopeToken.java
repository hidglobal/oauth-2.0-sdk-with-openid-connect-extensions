package com.nimbusds.openid.connect.messages;


/**
 * Enumeration of the standard {@link ScopeToken}s.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-09)
 */
public enum StdScopeToken implements ScopeToken {


	/**
	 * Informs the authorisation server that the client is making an OpenID 
	 * Connect request (REQUIRED). This scope tokens requests access to 
	 * the {@code user_id} claim. 
	 */
	OPENID("openid", ScopeToken.Type.REQUIRED),
	
	
	/**
	 * Requests that access to the end-user's default profile claims at the 
	 * UserInfo endpoint be granted by the issued access token. These claims
	 * are: {@code name}, {@code family_name}, {@code given_name}, 
	 * {@code middle_name}, {@code nickname}, {@code preferred_username}, 
	 * {@code profile}, {@code picture}, {@code website}, {@code gender}, 
	 * {@code birthday}, {@code zoneinfo}, {@code locale}, and 
	 * {@code updated_time}. 
	 */
	PROFILE("profile", ScopeToken.Type.OPTIONAL),
	
	
	/**
	 * Requests that access to the {@code email} and {@code email_verified}
	 * claims at the UserInfo endpoint be granted by the issued access 
	 * token.
	 */
	EMAIL("email", ScopeToken.Type.OPTIONAL),
	
	
	/**
	 * Requests that access to {@code address} claim at the UserInfo 
	 * endpoint be granted by the issued access token. 
	 */
	ADDRESS("address", ScopeToken.Type.OPTIONAL),
	
	
	/**
	 * Requests that access to the {@code phone_number} claim at the 
	 * UserInfo endpoint be granted by the issued access token. 
	 */
	PHONE("phone", ScopeToken.Type.OPTIONAL);


	/**
	 * The actual value.
	 */
	private String value;
	
	
	/**
	 * The requirement type.
	 */
	private ScopeToken.Type type;
	
	
	/**
	 * Creates a new scope token.
	 *
	 * @param value The scope token as a string.
	 * @param type  The requirement type.
	 */
	private StdScopeToken(final String value, final ScopeToken.Type type) {
	
		this.value = value;
		this.type = type;
	}
	
	
	@Override
	public String toString() {
	
		return value;
	}
	
	
	@Override
	public ScopeToken.Type getType() {
	
		return type;
	}
}
