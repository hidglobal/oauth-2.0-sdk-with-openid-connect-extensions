package com.nimbusds.openid.connect.sdk.claims;


import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;


/**
 * Object with an optional language tag (RFC 5646).
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Tags for Identifying Languages (RFC 5646).
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-22)
 */
public class LangTaggedObject<T> {


	/**
	 * The language tagged object.
	 */
	private final T object;


	/**
	 * The language tag, {@code null} if not specified.
	 */
	private final LangTag langTag;


	/**
	 * Creates a new language-tagged object with no tag.
	 *
	 * @param object  The object. Must not be {@code null}.
	 */
	public LangTaggedObject(final T object) {

		this(object, null);
	}


	/**
	 * Creates a new language-tagged object.
	 *
	 * @param object  The object to language-tag. Must not be {@code null}.
	 * @param langTag The language tag, {@code null} if not specified.
	 */
	public LangTaggedObject(final T object, final LangTag langTag) {

		if (object == null)
			throw new IllegalArgumentException("The tagged object must not be null");

		this.object = object;

		this.langTag = langTag;
	}


	/**
	 * Gets the language-tagged object.
	 *
	 * @return The object.
	 */
	public T getObject(){

		return object;
	}


	/**
	 * Gets the language tag.
	 *
	 * @return The language tag, {@code null} if not specified.
	 */
	public LangTag getLangTag() {

		return langTag;
	}


	/**
	 * Overrides {@code java.lang.Object.equals()}.
	 *
	 * @return Returns {@code true} if the other object is also a language
	 *         tagged object with the same value (object) and language tag.
	 */
	@Override
	public boolean equals(final Object other) {

		return other != null &&
		       other instanceof LangTaggedObject &&
		       ((LangTaggedObject)other).getObject().equals(getObject()) &&
		       ((LangTaggedObject)other).getLangTag() == getLangTag();
	}
}