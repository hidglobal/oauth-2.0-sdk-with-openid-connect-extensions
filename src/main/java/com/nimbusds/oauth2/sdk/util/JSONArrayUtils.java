package com.nimbusds.oauth2.sdk.util;


import net.minidev.json.JSONArray;

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * JSON array helper methods for parsing and typed retrieval of values.
 */
public class JSONArrayUtils {


	/**
	 * Parses a JSON array.
	 *
	 * <p>Specific JSON to Java entity mapping (as per JSON Simple):
	 *
	 * <ul>
	 *     <li>JSON numbers mapped to {@code java.lang.Number}.
	 *     <li>JSON integer numbers mapped to {@code long}.
	 *     <li>JSON fraction numbers mapped to {@code double}.
	 * </ul>
	 *
	 * @param s The JSON array string to parse. Must not be {@code null}.
	 *
	 * @return The JSON array.
	 *
	 * @throws ParseException If the string cannot be parsed to a JSON
	 *                        array.
	 */
	public static JSONArray parse(final String s)
		throws ParseException {

		Object o = JSONUtils.parseJSON(s);

		if (o instanceof JSONArray)
			return (JSONArray)o;
		else
			throw new ParseException("The JSON entity is not an array");
	}
}
