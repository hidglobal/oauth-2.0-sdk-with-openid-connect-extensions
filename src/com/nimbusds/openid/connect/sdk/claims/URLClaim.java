package com.nimbusds.openid.connect.sdk.claims;


import java.net.URL;


/**
 * The base abstract class for URL-based claims.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-08)
 */
public abstract class URLClaim implements Claim<URL> {


	/**
	 * The claim value.
	 */
	private URL value;
	
	
	@Override
	public URL getClaimValue() {
	
		return value;
	}
	
	
	@Override
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
	@Override
	public void setClaimValue(final URL value) {
	
		if (value == null)
			throw new IllegalArgumentException("The claim value must not be null");
		
		this.value = value;
	}
	
	
	@Override
	public String toString() {
	
		return this.getClaimName() + ": " + value.toString();
	}
	
	
	@Override
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
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof URLClaim &&
		       this.getClaimName().equals(((URLClaim)object).getClaimName()) &&
		       this.getClaimValue().equals(((URLClaim)object).getClaimValue());
	}
}
