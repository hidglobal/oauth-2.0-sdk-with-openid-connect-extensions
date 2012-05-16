package com.nimbusds.openid.connect.claims;


/**
 * The base abstract class for long integer based claims.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-20)
 */
public abstract class LongClaim implements Claim<Long> {


	/**
	 * The long value.
	 */
	private Long value;
	
	
	/**
	 * @inheritDoc
	 *
	 * @return The value as long integer.
	 */
	public Long getClaimValue() {
	
		return value;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public Claim.Type getType() {
	
		return Claim.Type.LONG;
	}
	
	
	/**
	 * @inheritDoc
	 *
	 * @param value The value as long integer.
	 *
	 * @throws IllegalArgumentException If the value is {@code null}.
	 */
	public void setClaimValue(final Long value) {
	
		if (value == null)
			throw new IllegalArgumentException("The time value must not be null");
		
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
	
		return object instanceof LongClaim &&
		       this.getClaimName().equals(((LongClaim)object).getClaimName()) &&
		       this.getClaimValue() == ((LongClaim)object).getClaimValue();
	}
}

