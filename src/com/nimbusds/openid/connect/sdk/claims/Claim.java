package com.nimbusds.openid.connect.sdk.claims;


import java.net.URL;

import javax.mail.internet.InternetAddress;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;


/**
 * Claim. A a piece of information about an entity that a claims provider 
 * asserts about that entity.
 *
 * <p>The claim is a name-value pair that serialises to a JSON boolean, string, 
 * number, array, object or null. Implementations should also override the
 * {@link #equals}, {@link #hashCode} and {@link #toString} methods.
 *
 * <p>Multiple claims forming a set are typically serialised into a JSON 
 * object:
 *
 * <pre>
 * {
 *   "sub"                : "248289761001",
 *   "name"               : "Jane Doe",
 *   "given_name"         : "Jane",
 *   "family_name"        : "Doe",
 *   "preferred_username" : "j.doe",
 *   "email"              : "janedoe@example.com",
 *   "picture"            : "http://example.com/janedoe/me.jpg"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-19)
 */
public interface Claim<T> {

	
	/**
	 * Enumeration of the claim requirement types.
	 */
	public static enum Requirement {

		/**
		 * Essential claim.
		 */
		ESSENTIAL,


		/**
		 * Voluntary claim.
		 */
		VOLUNTARY
	}


	/**
	 * Enumeration of the underlying claim value JSON types. Used in claim 
	 * parsing.
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
	 * Gets the claim name.
	 *
	 * @return The claim name. Must not be {@code null}.
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
	 * @return The JSON type of the claim value.
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
	
	
	/**
	 * Overrides {@code Object.equals()}.
	 *
	 * @param object The object to compare to.
	 *
	 * @return {@code true} if the two objects are claims with the same name
	 *         and value, otherwise {@code false}.
	 */
	@Override
	public boolean equals(final Object object);
	
	
	/**
	 * Returns a hash code based on the claim value.
	 *
	 * @return Hash code based on the claim value.
	 */
	@Override
	public int hashCode();
	
	
	/**
	 * Returns a string representation of the claim.
	 *
	 * <p>Format:
	 *
	 * <pre>
	 * claim-name: claim-value
	 * </pre>
	 *
	 * @return The string representation.
	 */
	@Override
	public String toString();
}
