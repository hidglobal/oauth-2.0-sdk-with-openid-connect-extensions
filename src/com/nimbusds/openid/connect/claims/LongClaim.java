package com.nimbusds.openid.connect.claims;


/**
 * The base abstract class for long integer based claims.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-08)
 */
public abstract class LongClaim implements Claim<Long> {


	/**
	 * The long value.
	 */
	private Long value;
	
	
	@Override
	public Long getClaimValue() {
	
		return value;
	}
	
	
	@Override
	public Claim.ValueType getClaimValueType() {
	
		return Claim.ValueType.LONG;
	}
	
	
	/**
	 * @inheritDoc
	 *
	 * @param value The value as long integer.
	 *
	 * @throws IllegalArgumentException If the value is {@code null}.
	 */
	@Override
	public void setClaimValue(final Long value) {
	
		if (value == null)
			throw new IllegalArgumentException("The time value must not be null");
		
		this.value = value;
	}
	
		
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof LongClaim &&
		       this.getClaimName().equals(((LongClaim)object).getClaimName()) &&
		       this.getClaimValue() == ((LongClaim)object).getClaimValue();
	}
	
	
	@Override
	public int hashCode() {
	
		return value.hashCode();
	}
	
	
	@Override
	public String toString() {
	
		return this.getClaimName() + ": " + value;
	}
}

