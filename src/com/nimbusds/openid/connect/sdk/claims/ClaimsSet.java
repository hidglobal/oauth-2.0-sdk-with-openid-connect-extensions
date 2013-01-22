package com.nimbusds.openid.connect.sdk.claims;


import java.net.MalformedURLException;
import java.net.URL;

import java.util.HashMap;
import java.util.Map;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;


/**
 * Claims set serialisable to a JSON object.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-22)
 */
public abstract class ClaimsSet {


	/**
	 * The JSON object representing the claims set.
	 */
	private JSONObject claims = new JSONObject();



	protected String getStringClaim(final String name) {

		Object value = claims.get(name);

		if (value != null && value instanceof String)
			return (String)value;
		else
			return null;
	}


	protected Map<LangTag,String> getLangTaggedStringClaims(final String name) {

		Map<LangTag,String> map = new HashMap<LangTag,String>();

		for (Map.Entry<String,Object> entry: claims.entrySet()) {

			if (! (entry.getValue() instanceof String))
				continue;

			
			if (entry.getKey().equals(name)) {

				// Claim name matches, no tag	
				map.put(null, (String)entry.getValue());
			}
			else if (entry.getKey().startsWith(name + '#')) {

				// Claim name matches, has tag
				String[] parts = entry.getKey().split("#", 2);

				LangTag langTag = null;

				if (parts.length == 2) {
					
					try {
						langTag = LangTag.parse(parts[1]);
						
					} catch (LangTagException e) {

						// ignore
					}
				}

				map.put(langTag, (String)entry.getValue());
			}
		}

		return map;
	}



	protected void setStringClaim(final String name, final String value) {

		if (value != null)
			claims.put(name, value);
		else
			claims.remove(name);
	}


	
	protected void setStringClaim(final String name, final LangTaggedObject<String> value) {

		if (value == null)
			return;

		else if (value.getLangTag() != null)
			claims.put(name + '#' + value.getLangTag(), value.getObject());
		else
			claims.put(name, value.getObject());
	}


	protected Boolean getBooleanClaim(final String name) {

		Object value = claims.get(name);

		if (value != null && value instanceof Boolean)
			return (Boolean)value;
		else
			return null;
	}


	protected void setBooleanClaim(final String name, final Boolean value) {

		if (value != null)
			claims.put(name, value);
		else
			claims.remove(name);
	}


	protected URL getURLClaim(final String name) {

		String value = getStringClaim(name);

		if (value == null)
			return null;

		try {
			return new URL(value);

		} catch (MalformedURLException e) {

			return null;
		}
	}


	protected void setURLClaim(final String name, final URL value) {

		if (value != null)
			claims.put(name, value.toString());
		else
			claims.remove(name);
	}


	protected InternetAddress getEmailClaim(final String name) {

		String value = getStringClaim(name);

		if (value == null)
			return null;

		try {
			return new InternetAddress(value);

		} catch (AddressException e) {

			return null;
		}
	}


	protected void setEmailClaim(final String name, final InternetAddress value) {

		if (value != null)
			claims.put(name, value.getAddress());
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
