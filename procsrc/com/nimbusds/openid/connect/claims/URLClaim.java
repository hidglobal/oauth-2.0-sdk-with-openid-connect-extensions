package com.nimbusds.openid.connect.claims;


import java.net.URL;


/**
 * The base abstract class for URL-based claims.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-04-20)
 */
public abstract class URLClaim implements Claim<URL> {


	/**
	 * The claim value.
	 */
	private URL value;
	
	
	/**
	 * @inheritDoc
	 *
	 * @return The claim value.
	 */
	public URL getClaimValue() {
	
		return value;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public Claim.ValueType getClaimValueType() {
	
		return Claim.ValueType.URL;
	}
	
	
	/**
	 * @inheritDoc
	 *
	 * @param value The claim value.
	 *
	 * @throws IllegalArgumentException If the value is {@code null}.
	 */
	public void setClaimValue(final URL value) {
	
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
	
		return object instanceof URLClaim &&
		       this.getClaimName().equals(((URLClaim)object).getClaimName()) &&
		       this.getClaimValue().equals(((URLClaim)object).getClaimValue());
	}
}
