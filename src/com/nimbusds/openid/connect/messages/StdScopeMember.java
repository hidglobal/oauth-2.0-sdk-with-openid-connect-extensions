package com.nimbusds.openid.connect.messages;


/**
 * Enumeration of the standard {@link ScopeMember}s.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-09)
 */
public enum StdScopeMember implements ScopeMember {


	/**
	 * Informs the authorisation server that the client is making an OpenID 
	 * Connect request (REQUIRED).
	 */
	OPENID("openid", ScopeMember.Type.REQUIRED),
	
	
	/**
	 * Requests that access to the end-user's default profile claims at the 
	 * UserInfo endpoint be granted by the issued access token.
	 */
	PROFILE("profile", ScopeMember.Type.OPTIONAL),
	
	
	/**
	 * Requests that access to the email and verified claims at the UserInfo
	 * endpoint be granted by the issued access token.
	 */
	EMAIL("email", ScopeMember.Type.OPTIONAL),
	
	
	/**
	 * Requests that access to address claim at the UserInfo endpoint be 
	 * granted by the issued access token. 
	 */
	ADDRESS("address", ScopeMember.Type.OPTIONAL),
	
	
	/**
	 * Requests that access to the phone_number claim at the UserInfo 
	 * endpoint be granted by the issued access token. 
	 */
	PHONE("phone", ScopeMember.Type.OPTIONAL);


	/**
	 * The actual value.
	 */
	private String value;
	
	
	/**
	 * The requirement type.
	 */
	private ScopeMember.Type type;
	
	
	/**
	 * Creates a new scope member.
	 *
	 * @param value The scope member as a string.
	 * @param type  The requirement type.
	 */
	private StdScopeMember(final String value, final ScopeMember.Type type) {
	
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
	public ScopeMember.Type getType() {
	
		return type;
	}
}
