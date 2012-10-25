package com.nimbusds.openid.connect.sdk.claims;


/**
 * Generic claim. It can be used to represent an arbitrary claim, e.g. a custom
 * claim outside the typted claims used in OpenID Connect.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-08)
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
	 * @param name The claim name. Must not be {@code null}.
	 */ 
	public GenericClaim(final String name) {
	
		if (name == null)
			throw new IllegalArgumentException("The claim name must not be null");
		
		this.name = name;
	}
	
	
	@Override
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
	@Override
	public Object getClaimValue() {
	
		return value;
	}
	
	
	/**
	 * Gets the claim type.
	 *
	 * @return The claim type, {@code null} if the claim value is not
	 *         specified.
	 */
	@Override
	public Claim.ValueType getClaimValueType() {
	
		return type;
	}
}
