package com.nimbusds.openid.connect.claims;


import com.nimbusds.langtag.LangTag;


/**
 * The base abstract class for string-based claims with optional language tag
 * (RFC 5646).
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
 *     <li>RFC 5646.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-23)
 */
public abstract class StringClaimWithLangTag extends StringClaim implements ClaimWithLangTag<String> {

	
	/**
	 * Optional language tag (RFC 5646).
	 */
	protected LangTag langTag = null;
	
	
	/**
	 * @inheritDoc
	 */
	public abstract String getBaseClaimName();
	
	
	/**
	 * @inheritDoc
	 */
	public void setLangTag(final LangTag langTag) {
	
		this.langTag = langTag;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public LangTag getLangTag() {
	
		return langTag;
	}
}
