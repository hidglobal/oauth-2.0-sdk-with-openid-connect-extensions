package com.nimbusds.openid.connect.messages;


/**
 * A token in the {@link Scope} parameter of an {@link AuthorizationRequest}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-06-11)
 */
public interface ScopeToken {


	/**
	 * Enumeration of the {@link ScopeToken scope token} requirement 
	 * types.
	 */
	public static enum Type {
	
		/**
		 * The token must be present in the {@link Scope} parameter.
		 */
		REQUIRED,
		
		
		/**
		 * The token may be optionally included in the {@link Scope}
		 * parameter.
		 */
		OPTIONAL;
	}
	

	/**
	 * Returns the string identifier of the scope token.
	 *
	 * @return The string identifier of the scope token.
	 */
	public String toString();
	
	
	/**
	 * Returns the requirement type of the scope token.
	 *
	 * @return The requirement type of the scope token.
	 */
	public Type getType();
}
