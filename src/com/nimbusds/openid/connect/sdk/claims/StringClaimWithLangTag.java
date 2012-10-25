package com.nimbusds.openid.connect.sdk.claims;


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
 *     <li>RFC 5646
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-08)
 */
public abstract class StringClaimWithLangTag extends StringClaim implements ClaimWithLangTag<String> {

	
	/**
	 * Optional language tag (RFC 5646).
	 */
	protected LangTag langTag = null;
	
	
	@Override
	public abstract String getBaseClaimName();
	
	
	/**
	 * @inheritDoc
	 *
	 * @return The base claim name if no language tag is present, else the
	 *         base claim name with the language tag appended.
	 */
	@Override
	public String getClaimName() {

		if (getLangTag() == null)
			return getBaseClaimName();
		else
			return getBaseClaimName() + getLangTag().toString();
	}
	
	
	@Override
	public void setLangTag(final LangTag langTag) {
	
		this.langTag = langTag;
	}
	
	
	@Override
	public LangTag getLangTag() {
	
		return langTag;
	}
}
