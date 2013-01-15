package com.nimbusds.oauth2.sdk;


import java.util.HashSet;

import net.jcip.annotations.NotThreadSafe;


/**
 * Authorisation scope. This class is not thread-safe.
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
	 * Returns the string representation of this scope.
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
	 * @param s The scope string. Must not be {@code null}.
	 */
	public static Scope parse(final String s) {

		Scope scope = new Scope();

		String[] tokens = s.split("\\s+");

		for (String t: tokens)
			scope.add(new ScopeToken(t));

		return scope;
	}
}
