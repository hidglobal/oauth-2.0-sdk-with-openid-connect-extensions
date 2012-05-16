package com.nimbusds.openid.connect.claims;


import java.net.MalformedURLException;
import java.net.URL;


/**
 * The base abstract class for string-based claims.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-20)
 */
public abstract class StringClaim implements Claim<String> {


	/**
	 * The claim value.
	 */
	private String value;
	
	
	/**
	 * @inheritDoc
	 *
	 * @return The claim value.
	 */
	public String getClaimValue() {
	
		return value;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public Claim.Type getType() {
	
		return Claim.Type.STRING;
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
	public void setClaimValue(final String value) {
	
		if (value == null || value.trim().isEmpty())
			throw new IllegalArgumentException("The claim value must not be null or empty");
		
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
	
		return object instanceof StringClaim &&
		       this.getClaimName().equals(((StringClaim)object).getClaimName()) &&
		       this.getClaimValue().equals(((StringClaim)object).getClaimValue());
	}
}
