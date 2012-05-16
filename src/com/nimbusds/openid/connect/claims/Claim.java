package com.nimbusds.openid.connect.claims;


import java.net.URL;

import javax.mail.internet.InternetAddress;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;


/**
 * Claim interface. A claim is a piece of information about an entity that a 
 * claims provider asserts about that entity.
 *
 * <p>A claim has a canonical name and a value that serialises to a JSON 
 * boolean, string, number, array, object or null.
 *
 * <p>Claims are typically serialised into a JSON object:
 *
 * <pre>
 * {
 *   "user_id"  : 123456789,
 *   "name"     : "Alice Wonderland",
 *   "email"    : "alice@wonderland.net",
 *   "verified" : true,
 *   "locales"  : ["en", "en-GB"],
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-16)
 */
public interface Claim<T> {

	
	/**
	 * Enumeration of the underlying claim value JSON types. Intended to be
	 * used in claim parsing.
	 */
	public static enum ValueType {
	
	
		/**
		 * JSON true|false.
		 */
		BOOLEAN,
		
		
		/**
		 * JSON number as java.lang.Integer.
		 */
		INTEGER,
		
		
		/**
		 * JSON number as java.lang.Long.
		 */
		LONG,
		
		
		/**
		 * JSON number as java.lang.Float.
		 */
		FLOAT,
		
		
		/**
		 * JSON number as java.lang.Double.
		 */
		DOUBLE,
		
		
		/**
		 * JSON string.
		 */
		STRING,
		
		
		/**
		 * JSON string as java.net.URL.
		 */
		URL,
		
		
		/**
		 * JSON string as javax.mail.internet.InternetAddress.
		 */
		EMAIL,
		
		
		/**
		 * JSON array.
		 */
		ARRAY,
		
		
		/**
		 * JSON object.
		 */
		OBJECT;
		
		
		/**
		 * Resolves the matching claim value type of the specified 
		 * object.
		 *
		 * @param o The object to check. May be {@code null}.
		 *
		 * @return The resolved claim value type, {@code null} if the 
		 *         object doesn't match an enumerated type or is 
		 *         {@code null}.
		 */
		public static ValueType resolve(final Object o) {
		
			if (o == null)
				return null;

			else if (o instanceof Boolean)
				return BOOLEAN;

			else if (o instanceof Integer)
				return INTEGER;

			else if (o instanceof Long)
				return LONG;

			else if (o instanceof Float)
				return FLOAT;

			else if (o instanceof Double)
				return DOUBLE;

			else if (o instanceof String)
				return STRING;
			
			else if (o instanceof URL)
				return URL;
				
			else if (o instanceof InternetAddress)
				return EMAIL;
				
			else if (o instanceof JSONArray)
				return ARRAY;
				
			else if (o instanceof JSONObject)
				return OBJECT;
				
			else
				return null;
		}
	}
	
	
	/**
	 * Gets the canonical claim name.
	 *
	 * @return The canonical claim name. Must not be {@code null}.
	 */
	public String getClaimName();
	
	
	/**
	 * Gets the claim value.
	 *
	 * @return The claim value, which may be a {@code java.lang.Boolean}, a 
	 *         {@code java.lang.String}, a {@code java.lang.Number}, a
	 *         {@code net.minidev.json.JSONArray}, a 
	 *         {@code nnet.minidev.json.JSONObject} or {@code null} if 
	 *         undefined.
	 */
	public T getClaimValue();
	
	
	
	/**
	 * Gets the JSON type of the claim value.
	 *
	 * @return The underlying JSON type of the claim value.
	 */
	public ValueType getClaimValueType();
	
	
	/**
	 * Sets the claim value.
	 *
	 * @param value The claim value, which may be a 
	 *              {@code java.lang.Boolean}, a {@code java.lang.String}, a 
	 *              {@code java.lang.Number}, a 
	 *              {@code net.minidev.json.JSONArray}, a 
	 *              {@code nnet.minidev.json.JSONObject} or {@code null} if 
	 *              undefined.
	 *
	 * @throws IllegalArgumentException If the value is not of the expected 
	 *                                  type for the claim.
	 */
	public void setClaimValue(final T value);
}
