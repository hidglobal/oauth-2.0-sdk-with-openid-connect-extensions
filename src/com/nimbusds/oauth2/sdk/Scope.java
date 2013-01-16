package com.nimbusds.oauth2.sdk;


import java.util.HashSet;

import net.jcip.annotations.NotThreadSafe;


/**
 * Authorisation scope. This class is not thread-safe.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 3.3.
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-15)
 */
@NotThreadSafe
public class Scope extends HashSet<ScopeToken> {

	
	/**
	 * Creates a new empty authorisation scope.
	 */
	public Scope() {
	
		// Nothing to do
	}
	
	
	/**
	 * Returns the string representation of this scope. The scope tokens
	 * can be serialised in any order.
	 *
	 * @return The string representation.
	 */
	@Override
	public String toString() {
	
		StringBuilder sb = new StringBuilder();
	
		for (ScopeToken token: this) {

			if (sb.length() > 0)
				sb.append(' ');
		
			sb.append(token.toString());
		}
	
		return sb.toString();
	}


	/**
	 * Parses a scope from the specified string representation.
	 *
	 * @param s The scope string, {@code null} if not specified.
	 *
	 * @return The scope, {@code null} if not specified.
	 */
	public static Scope parse(final String s) {

		if (s == null)
			return null;

		Scope scope = new Scope();

		String[] tokens = s.split("\\s+");

		for (String t: tokens)
			scope.add(new ScopeToken(t));

		return scope;
	}
}
