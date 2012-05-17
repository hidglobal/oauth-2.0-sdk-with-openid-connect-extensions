package com.nimbusds.openid.connect.claims;


import javax.mail.internet.InternetAddress;


/**
 * The base abstract class for email-based claims.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-04-20)
 */
public abstract class EmailClaim implements Claim<InternetAddress> {


	/**
	 * The claim value.
	 */
	private InternetAddress value;
	
	
	/**
	 * @inheritDoc
	 *
	 * @return The claim value.
	 */
	public InternetAddress getClaimValue() {
	
		return value;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public Claim.ValueType getClaimValueType() {
	
		return Claim.ValueType.EMAIL;
	}
	
	
	/**
	 * @inheritDoc
	 *
	 * @param value The claim value.
	 *
	 * @throws IllegalArgumentException If the value is {@code null}.
	 */
	public void setClaimValue(final InternetAddress value) {
	
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
	
		return this.getClaimName() + ": " + value.toString();
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
	
		return object instanceof EmailClaim &&
		       this.getClaimName().equals(((EmailClaim)object).getClaimName()) &&
		       this.getClaimValue().equals(((EmailClaim)object).getClaimValue());
	}
}
