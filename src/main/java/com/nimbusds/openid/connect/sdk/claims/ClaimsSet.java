package com.nimbusds.openid.connect.sdk.claims;


import java.net.URI;
import java.net.URL;
import java.util.*;

import javax.mail.internet.InternetAddress;

import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagUtils;

import com.nimbusds.jwt.JWTClaimsSet;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.DateUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Claims set serialisable to a JSON object.
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
	 * Puts all claims from the specified other claims set.
	 *
	 * @param other The other claims set. Must not be {@code null}.
	 */
	public void putAll(final ClaimsSet other) {

		putAll(other.claims);
	}


	/**
	 * Puts all claims from the specified map.
	 *
	 * @param claims The claims to put. Must not be {@code null}.
	 */
	public void putAll(final Map<String,Object> claims) {

		this.claims.putAll(claims);
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
	public <T> T getClaim(final String name, final Class<T> clazz) {

		try {
			return JSONObjectUtils.getGeneric(claims, name, clazz);
		} catch (ParseException e) {
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
	public <T> Map<LangTag,T> getLangTaggedClaim(final String name, final Class<T> clazz) {

		Map<LangTag,Object> matches = LangTagUtils.find(name, claims);
		Map<LangTag,T> out = new HashMap<>();

		for (Map.Entry<LangTag,Object> entry: matches.entrySet()) {

			LangTag langTag = entry.getKey();
			String compositeKey = name + (langTag != null ? "#" + langTag : "");

			try {
				out.put(langTag, JSONObjectUtils.getGeneric(claims, compositeKey, clazz));
			} catch (ParseException e) {
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
	public void setClaim(final String name, final Object value, final LangTag langTag) {

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

		try {
			return JSONObjectUtils.getString(claims, name);
		} catch (ParseException e) {
			return null;
		}
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

		return langTag == null ? getStringClaim(name) : getStringClaim(name + '#' + langTag);
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

		try {
			return JSONObjectUtils.getBoolean(claims, name);
		} catch (ParseException e) {
			return null;
		}
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

		try {
			return JSONObjectUtils.getNumber(claims, name);
		} catch (ParseException e) {
			return null;
		}
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

		try {
			return JSONObjectUtils.getURL(claims, name);
		} catch (ParseException e) {
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
	 * Gets an URI string based claim.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or parsing
	 *         failed.
	 */
	public URI getURIClaim(final String name) {

		try {
			return JSONObjectUtils.getURI(claims, name);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Sets an URI string based claim.
	 *
	 * @param name  The claim name. Must not be {@code null}.
	 * @param value The claim value. If {@code null} any existing claim
	 *              with the same name will be removed.
	 */
	public void setURIClaim(final String name, final URI value) {

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

		try {
			return JSONObjectUtils.getEmail(claims, name);
		} catch (ParseException e) {
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
	 * Gets a date / time based claim, represented as the number of seconds
	 * from 1970-01-01T0:0:0Z as measured in UTC until the date / time.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or parsing
	 *         failed.
	 */
	public Date getDateClaim(final String name) {

		try {
			return DateUtils.fromSecondsSinceEpoch(JSONObjectUtils.getNumber(claims, name).longValue());
		} catch (Exception e) {
			return null;
		}
	}


	/**
	 * Sets a date / time based claim, represented as the number of seconds
	 * from 1970-01-01T0:0:0Z as measured in UTC until the date / time.
	 *
	 * @param name  The claim name. Must not be {@code null}.
	 * @param value The claim value. If {@code null} any existing claim
	 *              with the same name will be removed.
	 */
	public void setDateClaim(final String name, final Date value) {

		if (value != null)
			setClaim(name, DateUtils.toSecondsSinceEpoch(value));
		else
			claims.remove(name);
	}


	/**
	 * Gets a string list based claim.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or parsing
	 *         failed.
	 */
	public List<String> getStringListClaim(final String name) {

		try {
			return Arrays.asList(JSONObjectUtils.getStringArray(claims, name));
		} catch (ParseException e) {
			return null;
		}
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
	public JSONObject toJSONObject() {

		return claims;
	}


	/**
	 * Gets the JSON Web Token (JWT) claims set for this claim set.
	 *
	 * @return The JWT claims set.
	 *
	 * @throws ParseException If the conversion to a JWT claims set fails.
	 */
	public JWTClaimsSet toJWTClaimsSet()
		throws ParseException {

		try {
			return JWTClaimsSet.parse(claims);

		} catch (java.text.ParseException e) {

			throw new ParseException(e.getMessage(), e);
		}
	}
}
