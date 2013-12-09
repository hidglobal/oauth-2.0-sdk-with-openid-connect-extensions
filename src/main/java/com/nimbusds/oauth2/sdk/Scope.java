package com.nimbusds.oauth2.sdk;


import java.util.*;

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
 *     <li>OAuth 2.0 (RFC 6749), section 3.3.
 * </ul>
 */
@NotThreadSafe
public class Scope extends LinkedHashSet<Scope.Value> {

	
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

			return object instanceof Value &&
			       this.toString().equals(object.toString());
		}
	}

	
	/**
	 * Creates a new empty authorisation scope.
	 */
	public Scope() {
		// Nothing to do
	}


	/**
	 * Creates a new authorisation scope with the specified values.
	 *
	 * @param values The values.
	 */
	public Scope(final Value ... values) {

		if (values == null)
			return;

		addAll(Arrays.asList(values));
	}
	
	
	/**
	 * Returns the string list representation of this scope. The scope
	 * values will be serialised in the order they were added.
	 * 
	 * @return The string list representation.
	 */
	public List<String> toStringList() {
		
		List<String> list = new ArrayList<String>(this.size());
		
		for (Scope.Value v: this)
			list.add(v.getValue());
		
		return list;
	}

	
	/**
	 * Returns the string representation of this scope. The scope values 
	 * will be serialised in the order they were added.
	 *
	 * @return The string representation.
	 */
	@Override
	public String toString() {

		StringBuilder sb = new StringBuilder();

		for (Scope.Value v : this) {

			if (sb.length() > 0) {
				sb.append(' ');
			}

			sb.append(v.toString());
		}

		return sb.toString();
	}
	
	
	/**
	 * Parses a scope from the specified string collection representation.
	 * 
	 * @param collection The string collection, {@code null} if not 
	 *                   specified.
	 * 
	 * @return The scope, {@code null} if not specified.
	 */
	public static Scope parse(final Collection<String> collection) {
		
		if (collection == null)
			return null;
		
		Scope scope = new Scope();
		
		for (String v: collection)
			scope.add(new Scope.Value(v));
		
		return scope;
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

		StringTokenizer st = new StringTokenizer(s, " ");

		while(st.hasMoreTokens())
			scope.add(new Scope.Value(st.nextToken()));

		return scope;
	}
}
