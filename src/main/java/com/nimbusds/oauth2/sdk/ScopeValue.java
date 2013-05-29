package com.nimbusds.oauth2.sdk;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Authorisation {@link Scope scope} value. This class is immutable.
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public class ScopeValue extends Identifier {


	/**
	 * Enumeration of the {@link ScopeValue scope value} requirements 
	 * for application-specific authorisation requests.
	 */
	public static enum Requirement {
	
		/**
		 * The value must be present in the {@link Scope} parameter.
		 */
		REQUIRED,
		
		
		/**
		 * The value may be optionally included in the {@link Scope}
		 * parameter.
		 */
		OPTIONAL
	}


	/**
	 * Optional requirement.
	 */
	private final ScopeValue.Requirement requirement;


	/**
	 * Creates a new scope value. The requirement is not specified.
	 *
	 * @param value The scope value. Must not be {@code null} or empty
	 *              string.
	 */
	public ScopeValue(final String value) {
	
		this(value, null);
	}


	/**
	 * Creates a new scope value with an optional requirement.
	 *
	 * @param value       The scope value. Must not be {@code null} or 
	 *                    empty string.
	 * @param requirement The requirement, {@code null} if not specified.
	 */
	public ScopeValue(final String value, final ScopeValue.Requirement requirement) {
	
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

		return object != null &&
		       object instanceof ScopeValue &&
		       this.toString().equals(object.toString());
	}
}
