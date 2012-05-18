package com.nimbusds.openid.connect.messages;


import java.util.HashSet;
import java.util.Set;

import com.nimbusds.openid.connect.ParseException;


/**
 * Set of {@link ResponseType}s.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Standard 1.0, section 2.2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-22)
 */
public class ResponseTypeSet extends HashSet<ResponseType> {


	/**
	 * Creates a new empty response type set.
	 */
	public ResponseTypeSet() {
	
	 	// Nothing to do
	}
	
	
	/**
	 * Parses a set of authorisation response types.
	 *
	 * <p>OpenID Connect specifies the following string vectors but this 
	 * method will allow other orders as well to accommodate sloppy 
	 * serialisers:
	 *
	 * <pre>
	 * code
	 * token
	 * id_token
	 * id_token token
	 * code token
	 * code id_token token
	 * </pre>
	 *
	 * @param s Space-delimited list of one or more individual authorisation
	 *          response types.
	 *
	 * @return The parsed authorisation response types set.
	 *
	 * @throws ParseException If the parsed string is {@code null}, empty or
	 *                        contains an invalid response type name.
	 */
	public static ResponseTypeSet parse(final String s)
		throws ParseException {
	
		if (s == null || s.trim().isEmpty())
			throw new ParseException("Couldn't parse response type: Null or empty string");
	
		ResponseTypeSet set = new ResponseTypeSet();
		
		String[] tokens = s.split("\\s+");
		
		for (String t: tokens)
			set.add(ResponseType.parse(t));
		
		return set;
	}
	
	
	/**
	 * Returns the canonical string representation of this set of 
	 * authorisation response types.
	 *
	 * <p>The serialised set is guaranteed to have one of the following
	 * orders (to conform with the OpenID Connect spec):
	 *
	 * <pre>
	 * code
	 * token
	 * id_token
	 * id_token token
	 * code token
	 * code id_token token
	 * </pre>
	 *
	 * @return Space-delimited string representing the authorisation 
	 *         response types.
	 */
	public String toString() {
	
		StringBuilder sb = new StringBuilder();
		
		if (contains(ResponseType.CODE)) {
		
			sb.append("code");
		}
		
		if (contains(ResponseType.ID_TOKEN)) {
		
			if (sb.length() > 0)
				sb.append(" id_token");
			else
				sb.append("id_token");
		}
		
		if (contains(ResponseType.TOKEN)) {
		
			if (sb.length() > 0)
				sb.append(" token");
			else
				sb.append("token");
		}
	
		return sb.toString();
	}
}
