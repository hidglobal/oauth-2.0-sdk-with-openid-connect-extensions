package com.nimbusds.openid.connect.sdk.claims;


/**
 * The base abstract class for boolean-based claims.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-08)
 */
public abstract class BooleanClaim implements Claim<Boolean> {


	/**
	 * The claim value.
	 */
	private Boolean value;
	
	
	@Override
	public Boolean getClaimValue() {
	
		return value;
	}
	
	
	@Override
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
	
	
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof BooleanClaim &&
		       this.getClaimName().equals(((BooleanClaim)object).getClaimName()) &&
		       this.getClaimValue().equals(((BooleanClaim)object).getClaimValue());
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
