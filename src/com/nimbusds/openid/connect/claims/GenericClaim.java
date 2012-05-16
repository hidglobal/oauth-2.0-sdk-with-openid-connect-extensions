package com.nimbusds.openid.connect.claims;


/**
 * Generic claim. It can be used to represent an arbitrary claim, e.g. a custom
 * claim outside the typed claims used in OpenID Connect.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-21)
 */
public class GenericClaim implements Claim<Object> {

	
	/**
	 * The claim name.
	 */
	private String name;
	
	 
	/**
	 * The claim value.
	 */
	private Object value = null;
	
	
	/**
	 * The claim value type.
	 */
	private Claim.ValueType type = null;
	
	
	/**
	 * Creates a new generic claim with the specified name.
	 *
	 * @param name  The claim name. Must not be {@code null}.
	 */ 
	public GenericClaim(final String name) {
	
		if (name == null)
			throw new NullPointerException("The claim name must not be null");
		
		this.name = name;
	}
	
	
	/**
	 * Gets the canonical claim name.
	 *
	 * @return The canonical claim name.
	 */
	public String getClaimName() {

		return name;
	}
	
	
	/**
	 * Sets the claim value.
	 *
	 * @param value The claim value. It must map to one of the supported
	 *              {@link Claim.ValueType claim types}. 
	 *
	 * @throws IllegalArgumentException If the value is {@code null} or its
	 *                                  type is not supported.
	 */
	public void setClaimValue(final Object value) {
	
		type = Claim.ValueType.resolve(value);
		
		if (type == null)
			throw new IllegalArgumentException("Unexpected claim value type");
	
		this.value = value;
	}
	
	
	/**
	 * Gets the claim value.
	 *
	 * @return The claim value. If defined (not {@code null}) it matches the 
	 *         type indicated by {@link #getClaimValueType}.
	 */
	public Object getClaimValue() {
	
		return value;
	}
	
	
	/**
	 * Gets the claim type.
	 *
	 * @return The claim type, {@code null} if the claim value is not
	 *         specified.
	 */
	public Claim.ValueType getClaimValueType() {
	
		return type;
	}
}
