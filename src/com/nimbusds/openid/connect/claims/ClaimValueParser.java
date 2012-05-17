package com.nimbusds.openid.connect.claims;


import java.net.MalformedURLException;
import java.net.URL;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.ParseException;

import com.nimbusds.openid.connect.util.JSONObjectUtils;


/**
 * Parses claim values from a JSON object containing a claims set.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-17)
 */
public class ClaimValueParser {

	
	/**
	 * Parses a claim value from the specified JSON object. Supports all 
	 * {@link Claim.ValueType claim JSON data types} expect
	 * {@link Claim.ValueType#ARRAY array} and {@link Claim.ValueType#OBJECT object}.
	 *
	 *
	 * @param o     The JSON object containing a member representing the
	 *              parsed claim. Must not be {@code null}.
	 * @param claim The claim. Its value will be set to the value of the 
	 *              JSON member with the matching key (name). Must not be 
	 *              {@code null}.
	 *
	 * @throws ParseException If the JSON object doesn't contain a member
	 *                        with a matching key (name), its value is
	 *                        {@code null} or of unexpected type.
	 */
	@SuppressWarnings("unchecked")
	public static void parse(final JSONObject o, final Claim claim) 
		throws ParseException {
		
		final String claimName = claim.getClaimName();
		
		switch (claim.getClaimValueType()) {
		
			case BOOLEAN:
				claim.setClaimValue(JSONObjectUtils.getBoolean(o, claimName));
				break;
		
			case INTEGER:
				claim.setClaimValue(JSONObjectUtils.getInt(o, claimName));
				break;
				
			case LONG:
				claim.setClaimValue(JSONObjectUtils.getLong(o, claimName));
				break;
				
			case FLOAT:
				claim.setClaimValue(JSONObjectUtils.getFloat(o, claimName));
				break;
				
			case DOUBLE:
				claim.setClaimValue(JSONObjectUtils.getDouble(o, claimName));
				break;
				
			case STRING:
				claim.setClaimValue(JSONObjectUtils.getString(o, claimName));
				break;
			
			case URL:
				URL url = null;
				
				try {
					url = new URL(JSONObjectUtils.getString(o, claimName));
					
				} catch (MalformedURLException e) {
				
					throw new ParseException("Invalid URL syntax for claim \"" + claimName + "\"", e);
				}
				
				claim.setClaimValue(url);
				break;
				
			case EMAIL:
				InternetAddress email = null;
				final boolean isStrict = true;
				
				try {
					email = new InternetAddress(JSONObjectUtils.getString(o, claimName), isStrict);
					
				} catch (AddressException e) {
				
					throw new ParseException("Invalid email syntax for claim \"" + claimName + "\"", e);
				}
				
				claim.setClaimValue(email);
				break;
			
			case ARRAY:
				claim.setClaimValue(JSONObjectUtils.getJSONArray(o, claimName));
				break;
				
			case OBJECT:
				claim.setClaimValue(JSONObjectUtils.getJSONObject(o, claimName));
				break;
			
			default:
				throw new ParseException("Unsupported type for claim \"" + claimName + "\"");
		}
	}


	/**
	 * Prevents instantiation.
	 */
	private ClaimValueParser() {
	
		// Nothing to do
	}
}
