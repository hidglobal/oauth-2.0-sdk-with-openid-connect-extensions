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
 * @version $version$ (2012-06-11)
 */
public enum StdScopeToken implements ScopeToken {


	/**
	 * Informs the authorisation server that the client is making an OpenID 
	 * Connect request (REQUIRED).
	 */
	OPENID("openid", ScopeToken.Type.REQUIRED),
	
	
	/**
	 * Requests that access to the end-user's default profile claims at the 
	 * UserInfo endpoint be granted by the issued access token.
	 */
	PROFILE("profile", ScopeToken.Type.OPTIONAL),
	
	
	/**
	 * Requests that access to the email and verified claims at the UserInfo
	 * endpoint be granted by the issued access token.
	 */
	EMAIL("email", ScopeToken.Type.OPTIONAL),
	
	
	/**
	 * Requests that access to address claim at the UserInfo endpoint be 
	 * granted by the issued access token. 
	 */
	ADDRESS("address", ScopeToken.Type.OPTIONAL),
	
	
	/**
	 * Requests that access to the phone_number claim at the UserInfo 
	 * endpoint be granted by the issued access token. 
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
	
	
	/**
	 * @inheritDoc
	 */
	public String toString() {
	
		return value;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public ScopeToken.Type getType() {
	
		return type;
	}
}
