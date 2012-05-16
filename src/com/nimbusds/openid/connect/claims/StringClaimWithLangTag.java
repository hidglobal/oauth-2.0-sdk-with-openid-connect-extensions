package com.nimbusds.openid.connect.claims;


import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;


/**
 * The base abstract class for string-based claims with optional language tag
 * (RFC 5646).
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-15)
 */
public abstract class StringClaimWithLangTag extends StringClaim {

	
	/**
	 * Optional language tag (RFC 5646).
	 */
	protected LangTag langTag = null;
	
	
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
