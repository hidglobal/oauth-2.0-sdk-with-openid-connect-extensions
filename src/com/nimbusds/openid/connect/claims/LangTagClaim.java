package com.nimbusds.openid.connect.claims;


import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;


/**
 * The base abstract class for language tag (RFC 5646) based claims.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>RFC 5646.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-20)
 */
public abstract class LangTagClaim implements Claim<String> {


	/**
	 * The claim value.
	 */
	private LangTag value;
	
	
	/**
	 * @inheritDoc
	 *
	 * @return The claim value.
	 */
	public String getClaimValue() {
	
		return value.toString();
	}
	
	
	/**
	 * @inheritDoc
	 */
	public Claim.ValueType getClaimValueType() {
	
		return Claim.ValueType.STRING;
	}
	
	
	/**
	 * Gets the claim value as a language tag (RFC 5646).
	 *
	 * @return The claim value.
	 */
	public LangTag getClaimLangTagValue() {
	
		return value;
	}
	
	
	/**
	 * @inheritDoc
	 *
	 * @param value The claim value.
	 *
	 * @throws IllegalArgumentException If the value is {@code null}, empty
	 *                                  string or invalid language tag.
	 */
	public void setClaimValue(final String value) {
	
		if (value == null || value.trim().isEmpty())
			throw new IllegalArgumentException("The claim value must not be null or empty");
		
		try {
			this.value = LangTag.parse(value);
			
		} catch (LangTagException e) {
		
			throw new IllegalArgumentException("Invalid claim value: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Sets the claim value.
	 *
	 * @param value The claim value.
	 *
	 * @throws IllegalArgumentException If the value is {@code null}.
	 */
	public void setClaimValue(final LangTag value) {
		
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
	
		return object instanceof LangTagClaim &&
		       this.getClaimName().equals(((LangTagClaim)object).getClaimName()) &&
		       this.getClaimValue().equals(((LangTagClaim)object).getClaimValue());
	}
}
