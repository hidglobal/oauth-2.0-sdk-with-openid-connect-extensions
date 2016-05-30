package com.nimbusds.oauth2.sdk.util;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.nimbusds.oauth2.sdk.ParseException;
import net.minidev.json.JSONArray;
import org.apache.commons.collections.CollectionUtils;


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


	/**
	 * Converts the specified JSON array to a string list.
	 *
	 * @param jsonArray The JSON array. May be {@code null}.
	 *
	 * @return The corresponding string list, empty list if the JSON array
	 *         is {@code null} or empty.
	 */
	public static List<String> toStringList(final JSONArray jsonArray) {

		if (CollectionUtils.isEmpty(jsonArray)) {
			return Collections.emptyList();
		}

		List<String> stringList = new ArrayList<>(jsonArray.size());

		for (Object o: jsonArray) {

			if (o == null) {
				continue; // skip
			}

			stringList.add(o.toString());
		}

		return stringList;
	}


	/**
	 * Converts the specified JSON array to a URI list.
	 *
	 * @param jsonArray The JSON array. May be {@code null}.
	 *
	 * @return The corresponding URI list, empty list if the JSON array is
	 *         {@code null} or empty.
	 *
	 * @throws ParseException If a JSON array item couldn't be parsed to a
	 *                        URI.
	 */
	public static List<URI> toURIList(final JSONArray jsonArray)
		throws ParseException {

		if (CollectionUtils.isEmpty(jsonArray)) {
			return Collections.emptyList();
		}

		List<URI> uriList = new ArrayList<>(jsonArray.size());

		for (Object o: jsonArray) {

			if (o == null) {
				continue; // skip
			}

			try {
				uriList.add(new URI(o.toString()));
			} catch (URISyntaxException e) {
				throw new ParseException("Illegal URI: " + e.getMessage(), e);
			}
		}

		return uriList;
	}
}
