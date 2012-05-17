package com.nimbusds.openid.connect.claims;


import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;


/**
 * The base abstract class for string-based claims with optional language tag
 * (RFC 5646).
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-05-16)
 */
public abstract class StringClaimWithLangTag extends StringClaim {

	
	/**
	 * Optional language tag (RFC 5646).
	 */
	protected LangTag langTag = null;
	
	
	/**
	 * Gets the base claim name (without the language tag designation).
	 *
	 * @return The base claim name.
	 */
	public abstract String getBaseClaimName();
	
	
	/**
	 * Sets the language tag (RFC 5646).
	 *
	 * @param langTag The language tag, {@code null} if none.
	 */
	public void setLangTag(final LangTag langTag) {
	
		this.langTag = langTag;
	}
	
	
	/**
	 * Gets the language tag (RFC 5646).
	 *
	 * @return The language tag, {@code null} if none.
	 */
	public LangTag getLangTag() {
	
		return langTag;
	}
}
