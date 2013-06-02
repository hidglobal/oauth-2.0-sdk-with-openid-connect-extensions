package com.nimbusds.openid.connect.sdk.claims;


import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagUtil;


/**
 * Claims set serialisable to a JSON object.
 *
 * @author Vladimir Dzhuvinov
 */
public abstract class ClaimsSet {


	/**
	 * The JSON object representing the claims set.
	 */
	private final JSONObject claims;


	/**
	 * Creates a new empty claims set.
	 */
	protected ClaimsSet() {

		claims = new JSONObject();
	}


	/**
	 * Creates a new claims set from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 */
	protected ClaimsSet(final JSONObject jsonObject) {

		if (jsonObject == null)
			throw new IllegalArgumentException("The JSON object must not be null");

		claims = jsonObject;
	}


	/**
	 * Gets a claim.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified.
	 */
	public Object getClaim(final String name) {

		return claims.get(name);
	}


	/**
	 * Gets a claim that casts to the specified class.
	 *
	 * @param name  The claim name. Must not be {@code null}.
	 * @param clazz The Java class that the claim value should cast to.
	 *              Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or casting
	 *         failed.
	 */
	@SuppressWarnings("unchecked")
	public <T> T getClaim(final String name, final Class<T> clazz) {

		try {
			return (T)claims.get(name);

		} catch (ClassCastException e) {

			return null;
		}
	}


	/**
	 * Returns a map of all instances, including language-tagged, of a 
	 * claim with the specified base name.
	 *
	 * <p>Example JSON serialised claims set:
	 *
	 * <pre>
	 * {
	 *   "month"    : "January",
	 *   "month#de" : "Januar"
	 *   "month#es" : "enero",
	 *   "month#it" : "gennaio"
	 * }
	 * </pre>
	 *
	 * <p>The "month" claim instances as java.util.Map:
	 *
	 * <pre>
	 * null => "January" (no language tag)
	 * "de" => "Januar"
	 * "es" => "enero"
	 * "it" => "gennaio"
	 * </pre>
	 *
	 * @param name  The claim name. Must not be {@code null}.
	 * @param clazz The Java class that the claim values should cast to.
	 *              Must not be {@code null}.
	 *
	 * @return The matching language-tagged claim values, empty map if
	 *         none. A {@code null} key indicates the value has no language
	 *         tag (corresponds to the base name).
	 */
	@SuppressWarnings("unchecked")
	public <T> Map<LangTag,T> getLangTaggedClaim(final String name, final Class<T> clazz) {

		Map<LangTag,Object> matches = LangTagUtil.find(name, claims);

		Map<LangTag,T> out = new HashMap<LangTag,T>();

		for (Map.Entry<LangTag,Object> entry: matches.entrySet()) {

			try {
				out.put(entry.getKey(), (T)entry.getValue());

			} catch (ClassCastException e) {
				// skip
			}
		}

		return out;
	}


	/**
	 * Sets a claim.
	 *
	 * @param name  The claim name, with an optional language tag. Must not
	 *              be {@code null}.
	 * @param value The claim value. Should serialise to a JSON entity. If
	 *              {@code null} any existing claim with the same name will
	 *              be removed.
	 */
	public void setClaim(final String name, final Object value) {

		if (value != null)
			claims.put(name, value);
		else
			claims.remove(name);
	}


	/**
	 * Sets a claim with an optional language tag.
	 *
	 * @param name    The claim name. Must not be {@code null}.
	 * @param value   The claim value. Should serialise to a JSON entity.
	 *                If {@code null} any existing claim with the same name 
	 *                and language tag (if any) will be removed.
	 * @param langTag The language tag of the claim value, {@code null} if
	 *                not tagged.
	 */
	public <T> void setClaim(final String name, final Object value, final LangTag langTag) {

		String keyName = langTag != null ? name + "#" + langTag : name;
		
		setClaim(keyName, value);
	}


	/**
	 * Gets a string-based claim.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or casting
	 *         failed.
	 */
	public String getStringClaim(final String name) {

		return getClaim(name, String.class);
	}


	/**
	 * Gets a string-based claim with an optional language tag.
	 *
	 * @param name    The claim name. Must not be {@code null}.
	 * @param langTag The language tag of the claim value, {@code null} to 
	 *                get the non-tagged value.
	 *
	 * @return The claim value, {@code null} if not specified or casting
	 *         failed.
	 */
	public String getStringClaim(final String name, final LangTag langTag) {
	
		if (langTag == null)
			return getStringClaim(name);
		else
			return getStringClaim(name + '#' + langTag);
	}


	/**
	 * Gets a boolean-based claim.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or casting
	 *         failed.
	 */
	public Boolean getBooleanClaim(final String name) {

		return getClaim(name, Boolean.class);
	}


	/**
	 * Gets a number-based claim.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or casting
	 *         failed.
	 */
	public Number getNumberClaim(final String name) {

		return getClaim(name, Number.class);
	}


	/**
	 * Gets an URL string based claim.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or parsing
	 *         failed.
	 */
	public URL getURLClaim(final String name) {

		String value = getStringClaim(name);

		if (value == null)
			return null;

		try {
			return new URL(value);

		} catch (MalformedURLException e) {

			return null;
		}
	}


	/**
	 * Sets an URL string based claim.
	 *
	 * @param name  The claim name. Must not be {@code null}.
	 * @param value The claim value. If {@code null} any existing claim 
	 *              with the same name will be removed.
	 */
	public void setURLClaim(final String name, final URL value) {

		if (value != null)
			setClaim(name, value.toString());
		else
			claims.remove(name);
	}


	/**
	 * Gets an email string based claim.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or parsing
	 *         failed.
	 */
	public InternetAddress getEmailClaim(final String name) {

		String value = getStringClaim(name);

		if (value == null)
			return null;

		try {
			return new InternetAddress(value);

		} catch (AddressException e) {

			return null;
		}
	}


	/**
	 * Sets an email string based claim.
	 *
	 * @param name  The claim name. Must not be {@code null}.
	 * @param value The claim value. If {@code null} any existing claim 
	 *              with the same name will be removed.
	 */
	public void setEmailClaim(final String name, final InternetAddress value) {

		if (value != null)
			setClaim(name, value.getAddress());
		else
			claims.remove(name);
	}
	
	
	/**
	 * Gets the JSON object representation of this claims set.
	 *
	 * <p>Example:
	 * 
	 * <pre>
	 * {
	 *   "country"       : "USA",
	 *   "country#en"    : "USA",
	 *   "country#de_DE" : "Vereinigte Staaten",
	 *   "country#fr_FR" : "Etats Unis"
	 * }
	 * </pre>
	 *
	 * @return The JSON object representation.
	 */
	public JSONObject getJSONObject() {
	
		return claims;
	}
}
