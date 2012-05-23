package com.nimbusds.openid.connect.claims;


import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;


/**
 * Parser for claim names with optional language tag (RFC 5646).
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>RFC 5646
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-23)
 */
public class ClaimName {


	/**
	 * The base name.
	 */
	private String base;
	
	
	/**
	 * The optional language tag.
	 */
	private LangTag langTag = null;
	
	
	/**
	 * Creates a new claim name.
	 *
	 * @param base    The base of the claim name. Must not be {@code null}.
	 * @param langTag The language tag, {@code null} if none.
	 */
	private ClaimName(final String base, final LangTag langTag) {
	
		if (base == null)
			throw new NullPointerException("The claim name base must not be null");
		
		this.base = base;
		
		this.langTag = langTag;
	}
	
	
	/**
	 * Gets the full claim name (base + optional language tag).
	 *
	 * @return The full claim name.
	 */
	public String getName() {
	
		if (langTag == null)
			return getBase();
		
		else
			return getBase() + '#' + langTag.toString();
	}
	
	
	/**
	 * Gets the base of the claim name.
	 *
	 * @return The base of the claim name.
	 */
	public String getBase() {
	
		return base;
	}
	
	
	/**
	 * Gets the optional language tag.
	 *
	 * @return The language tag, {@code null} if none.
	 */
	public LangTag getLangTag() {
	
		return langTag;
	}
	
	
	/**
	 * Returns the string representation of this claim name.
	 *
	 * <p>See {@link #getName}.
	 *
	 * @return The full claim name.
	 */
	public String toString() {
	
		return getName();
	}
	
	
	/**
	 * Parses the specified string for a claim name with an optional 
	 * language tag. If no valid language tag is found, the entire parsed
	 * string becomes the {@link #getBase base} of the claim name.
	 *
	 * @param name The string representation of the full claim name (base
	 *             name + optional language tag).
	 *
	 * @return The claim name with optional language tag.
	 */
	public static ClaimName parse(final String name) {

		if (name == null)
			return null;
		
		String[] parts = name.split("#", 2);
		
		String base = parts[0];
		
		if (parts.length == 1)
			return new ClaimName(base, null);
		
		LangTag langTag = null;
		
		try {
			langTag = LangTag.parse(parts[1]);
			
		} catch (LangTagException e) {
		
			return new ClaimName(name, null);
		}

		return new ClaimName(base, langTag);
	}


}
