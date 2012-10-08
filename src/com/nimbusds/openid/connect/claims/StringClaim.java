package com.nimbusds.openid.connect.claims;


import java.net.MalformedURLException;
import java.net.URL;


/**
 * The base abstract class for string-based claims.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-08)
 */
public abstract class StringClaim implements Claim<String> {


	/**
	 * The claim value.
	 */
	private String value;
	
	
	@Override
	public String getClaimValue() {
	
		return value;
	}
	
	
	@Override
	public Claim.ValueType getClaimValueType() {
	
		return Claim.ValueType.STRING;
	}
	
	
	/**
	 * Checks if the claim value is an URL.
	 *
	 * @return {@code true} if the claim value is an URL, else 
	 *         {@code false}.
	 */
	public boolean isURL() {
	
		try {
			new URL(value);
			return true;
		
		} catch (MalformedURLException e) {
		
			return false;
		}
	}
	
	
	/**
	 * @inheritDoc
	 *
	 * @param value The claim value.
	 *
	 * @throws IllegalArgumentException If the value is {@code null} or 
	 *                                  empty string.
	 */
	@Override
	public void setClaimValue(final String value) {
	
		if (value == null || value.trim().isEmpty())
			throw new IllegalArgumentException("The claim value must not be null or empty");
		
		this.value = value;
	}
	
		
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof StringClaim &&
		       this.getClaimName().equals(((StringClaim)object).getClaimName()) &&
		       this.getClaimValue().equals(((StringClaim)object).getClaimValue());
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
