package com.nimbusds.oauth2.sdk;


import java.util.HashSet;

import net.jcip.annotations.NotThreadSafe;


/**
 * Authorisation scope. This class is not thread-safe.
 *
 * <p>Example scope from OpenID Connect indicating access to the user's email
 * and profile details:
 *
 * <pre>
 * Scope scope = new Scope();
 * scope.add(OIDCScopeValue.OPENID);
 * scope.add(OIDCScopeValue.EMAIL);
 * scope.add(OIDCScopeValue.PROFILE);
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 3.3.
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 */
@NotThreadSafe
public class Scope extends HashSet<ScopeValue> {

	
	/**
	 * Creates a new empty authorisation scope.
	 */
	public Scope() {
	
		// Nothing to do
	}
	
	
	/**
	 * Returns the string representation of this scope. The scope values
	 * may be serialised in any order.
	 *
	 * @return The string representation.
	 */
	@Override
	public String toString() {
	
		StringBuilder sb = new StringBuilder();
	
		for (ScopeValue token: this) {

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

		if (s.trim().isEmpty())
			return scope;

		String[] tokens = s.split("\\s+");

		for (String t: tokens)
			scope.add(new ScopeValue(t));

		return scope;
	}
}
