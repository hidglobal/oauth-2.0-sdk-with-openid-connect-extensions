package com.nimbusds.openid.connect.claims;


import com.nimbusds.langtag.LangTag;


/**
 * Claim with an optional language tag (RFC 5646).
 *
 * <p>Example claims with language tags:
 *
 * <pre>
 * {
 *   "family_name"            : "family name with no language tag",
 *   "family_name#ja-Kana-JP" : "family name, in Japanese, Katakana script",
 *   "family_name#ja-Hani-JP" : "family name, in Japanese, Kanji script",
 * }
 * </pre>
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
public interface ClaimWithLangTag<T> extends Claim<T> {

	
	/**
	 * Gets the base claim name (without the language tag designation).
	 *
	 * <p>Examples:
	 *
	 * <pre>
	 * "family_name"            // base claim name
	 * "faimly_name#ja-Kana-JP" // base claim name with language tag
	 * </pre>
	 *
	 * @return The base claim name.
	 */
	public String getBaseClaimName();
	
	
	/**
	 * Sets the language tag (RFC 5646).
	 *
	 * @param langTag The language tag, {@code null} if none.
	 */
	public void setLangTag(final LangTag langTag);
	
	
	/**
	 * Gets the language tag (RFC 5646).
	 *
	 * @return The language tag, {@code null} if none.
	 */
	public LangTag getLangTag();
}
