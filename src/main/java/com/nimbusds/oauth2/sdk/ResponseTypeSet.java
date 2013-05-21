package com.nimbusds.oauth2.sdk;


import java.util.HashSet;

import net.jcip.annotations.NotThreadSafe;

import org.apache.commons.lang3.StringUtils;


/**
 * Set of authorisation {@link ResponseType}s. This class is not thread-safe.
 *
 * <p>Provides helper methods to determine if the OAuth 2.0 protocol flow 
 * implied by the response type set is implicit flow or code flow:
 *
 * <ul>
 *     <li>{@link #impliesImplicitFlow}
 *     <li>{@link #impliesCodeFlow}
 * </ul>
 *
 * <p>Example response type set with code only (implies code flow):
 *
 * <pre>
 * ResponseTypeSet() rts = new ResponseTypeSet();
 * rts.add(ResponseType.CODE);
 * </pre>
 *
 * <p>Example OpenID Connect response type set with ID token and access token
 * (implies implicit flow):
 *
 * <pre>
 * ResponseTypeSet() rts = new ResponseTypeSet();
 * rts.add(ResponseType.TOKEN);
 * rts.add(OIDCResponseType.ID_TOKEN);
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 3.1.1 and 4.1.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@NotThreadSafe
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
	 * <p>Example serialised response type sets:
	 *
	 * <pre>
	 * code
	 * code id_token
	 * id_token
	 * token
	 * token id_token
	 * code token
	 * code token id_token
	 * </pre>
	 *
	 * @param s Space-delimited list of one or more authorisation response 
	 *          types.
	 *
	 * @return The authorisation response types set.
	 *
	 * @throws ParseException If the parsed string is {@code null} or 
	 *                        empty.
	 */
	public static ResponseTypeSet parse(final String s)
		throws ParseException {
	
		if (StringUtils.isBlank(s))
			throw new ParseException("Null or empty response type set string");
	
		ResponseTypeSet set = new ResponseTypeSet();
		
		String[] tokens = s.split("\\s+");
		
		for (String t: tokens)
			set.add(new ResponseType(t));
		
		return set;
	}
	
	
	/**
	 * Returns {@code true} if this reponse type set implies a code flow.
	 * This is determined by checking for the presence of {@code code} in
	 * the response type set.
	 *
	 * @return {@code true} if a code flow is implied, else {@code false}.
	 */
	public boolean impliesCodeFlow() {
	
		if (this.contains(ResponseType.CODE))
			return true;
		else
			return false;
	}
	
	
	/**
	 * Returns {@code true} if this reponse type set implies an implicit 
	 * flow. This is determined by checking for the absence of {@code code}
	 * in the response type set.
	 *
	 * @return {@code true} if an implicit flow is implied, else 
	 *         {@code false}.
	 */
	public boolean impliesImplicitFlow() {
	
		if (! this.contains(ResponseType.CODE))
			return true;
		else
			return false;
	}
	
	
	/**
	 * Returns the string representation of this set of authorisation 
	 * response types.
	 *
	 * <p>Example serialised response type sets:
	 *
	 * <pre>
	 * code
	 * code id_token
	 * id_token
	 * token
	 * token id_token
	 * code token
	 * code token id_token
	 * </pre>
	 *
	 * @return Space delimited string representing the authorisation 
	 *         response types.
	 */
	public String toString() {
	
		StringBuilder sb = new StringBuilder();

		for (ResponseType rt: this) {

			if (sb.length() > 0)
				sb.append(' ');

			sb.append(rt.getValue());
		}

		return sb.toString();
	}
}
