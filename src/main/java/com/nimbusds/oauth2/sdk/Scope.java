package com.nimbusds.oauth2.sdk;


import java.util.HashSet;

import net.jcip.annotations.Immutable;
import net.jcip.annotations.NotThreadSafe;

import com.nimbusds.oauth2.sdk.id.Identifier;


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
 * <li>OAuth 2.0 (RFC 6749), section 3.3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@NotThreadSafe
public class Scope extends HashSet<Scope.Value> {

	
	/**
	 * Authorisation scope value. This class is immutable.
	 */
	@Immutable
	public static class Value extends Identifier {

		/**
		 * Enumeration of the scope value requirements for 
		 * application-specific authorisation requests.
		 */
		public static enum Requirement {

			/**
			 * The value must be present in the {@link Scope}
			 * parameter.
			 */
			REQUIRED,
			/**
			 * The value may be optionally included in the
			 * {@link Scope} parameter.
			 */
			OPTIONAL
		}
		
		
		/**
		 * Optional requirement.
		 */
		private final Value.Requirement requirement;

		/**
		 * Creates a new scope value. The requirement is not specified.
		 *
		 * @param value The scope value. Must not be {@code null} or
		 *              empty string.
		 */
		public Value(final String value) {

			this(value, null);
		}

		/**
		 * Creates a new scope value with an optional requirement.
		 *
		 * @param value       The scope value. Must not be {@code null} 
		 *                    or empty string.
		 * @param requirement The requirement, {@code null} if not
		 *                    specified.
		 */
		public Value(final String value, final Requirement requirement) {

			super(value);

			this.requirement = requirement;
		}

		/**
		 * Gets the requirement of this scope value.
		 *
		 * @return The requirement, {@code null} if not specified.
		 */
		public Requirement getRequirement() {

			return requirement;
		}

		@Override
		public boolean equals(final Object object) {

			return object != null
				&& object instanceof Value
				&& this.toString().equals(object.toString());
		}
	}

	
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

		for (Scope.Value token : this) {

			if (sb.length() > 0) {
				sb.append(' ');
			}

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

		if (s == null) {
			return null;
		}

		Scope scope = new Scope();

		if (s.trim().isEmpty()) {
			return scope;
		}

		String[] tokens = s.split("\\s+");

		for (String t : tokens) {
			scope.add(new Scope.Value(t));
		}

		return scope;
	}
}
