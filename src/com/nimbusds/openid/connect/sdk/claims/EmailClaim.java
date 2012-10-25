package com.nimbusds.openid.connect.sdk.claims;


import javax.mail.internet.InternetAddress;


/**
 * The base abstract class for email-based claims.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-08)
 */
public abstract class EmailClaim implements Claim<InternetAddress> {


	/**
	 * The claim value.
	 */
	private InternetAddress value;
	
	
	@Override
	public InternetAddress getClaimValue() {
	
		return value;
	}
	
	
	@Override
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
	
	
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof EmailClaim &&
		       this.getClaimName().equals(((EmailClaim)object).getClaimName()) &&
		       this.getClaimValue().equals(((EmailClaim)object).getClaimValue());
	}
	
	
	@Override
	public int hashCode() {
	
		return value.hashCode();
	}
	
	
	@Override
	public String toString() {
	
		return this.getClaimName() + ": " + value.toString();
	}
}
