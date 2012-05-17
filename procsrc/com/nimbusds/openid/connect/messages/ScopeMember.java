package com.nimbusds.openid.connect.messages;


/**
 * A member in the {@link Scope} parameter of an {@link AuthorizationRequest}.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-04-09)
 */
public interface ScopeMember {


	/**
	 * Enumeration of the {@link ScopeMember scope member} requirement 
	 * types.
	 */
	public static enum Type {
	
		/**
		 * The member must be present in the {@link Scope} parameter.
		 */
		REQUIRED,
		
		
		/**
		 * The member may be optionally included in the {@link Scope}
		 * parameter.
		 */
		OPTIONAL;
	}
	

	/**
	 * Returns the string identifier of the scope member.
	 *
	 * @return The string identifier of the scope member.
	 */
	public String toString();
	
	
	/**
	 * Returns the requirement type of the scope member.
	 *
	 * @return The requirement type of the scope member.
	 */
	public Type getType();
}
