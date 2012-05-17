package com.nimbusds.openid.connect.claims;


/**
 * The base abstract class for boolean-based claims.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-04-20)
 */
public abstract class BooleanClaim implements Claim<Boolean> {


	/**
	 * The claim value.
	 */
	private Boolean value;
	
	
	/**
	 * @inheritDoc
	 *
	 * @return The claim value.
	 */
	public Boolean getClaimValue() {
	
		return value;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public Claim.ValueType getClaimValueType() {
	
		return Claim.ValueType.BOOLEAN;
	}
	
	
	/**
	 * @inheritDoc
	 *
	 * @param value The claim value.
	 *
	 * @throws IllegalArgumentException If the value is {@code null}.
	 */
	public void setClaimValue(final Boolean value) {
	
		if (value == null)
			throw new IllegalArgumentException("The claim value must not be null");
		
		this.value = value;
	}
	
	
	/**
	 * Returns the string representation of this claim.
	 *
	 * @return The string representation.
	 */
	public String toString() {
	
		return this.getClaimName() + ": " + value;
	}
	
	
	/**
	 * Overrides {@code Object.hashCode()}.
	 *
	 * @return The object hash code.
	 */
	public int hashCode() {
	
		return value.hashCode();
	}
	
		
	/**
	 * Overrides {@code Object.equals()}.
	 *
	 * @param object The object to compare to.
	 *
	 * @return {@code true} if the objects have the same claim name and 
	 *         value, otherwise {@code false}.
	 */
	public boolean equals(final Object object) {
	
		return object instanceof BooleanClaim &&
		       this.getClaimName().equals(((BooleanClaim)object).getClaimName()) &&
		       this.getClaimValue().equals(((BooleanClaim)object).getClaimValue());
	}
}
