package com.nimbusds.openid.connect.sdk;


import java.util.*;

import net.jcip.annotations.NotThreadSafe;

import org.apache.commons.lang3.StringUtils;

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Prompts for end-user re-authentication and consent.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 3.1.2.1.
 * </ul>
 */
@NotThreadSafe
public class Prompt extends LinkedHashSet<Prompt.Type> {


	/**
	 * Enumeration of the prompt types.
	 */
	public static enum Type {
	
	
		/** 
		 * The authorisation server must not display any authentication 
		 * or consent UI pages. An error is returned if the end user is 
		 * not already authenticated or the client does not have 
		 * pre-configured consent for the requested {@code scope}. This 
		 * can be used as a method to check for existing authentication 
		 * and / or consent.
		 */
		NONE,


		/**
		 * The authorisation server must prompt the end-user for 
		 * re-authentication.
		 */
		LOGIN,


		/**
		 * The authorisation server must prompt the end-user for 
		 * consent before returning information to the client.
		 */
		CONSENT,


		/**
		 * The authorisation server must prompt the end-user to select
		 * a user account. This allows a user who has multiple accounts 
		 * at the authorisation server to select amongst the multiple 
		 * accounts that they may have current sessions for.
		 */
		SELECT_ACCOUNT;
		
		
		/**
		 * Returns the string identifier of this prompt type.
		 *
		 * @return The string identifier.
		 */
		@Override
		public String toString() {
		
			return super.toString().toLowerCase();
		}
		
		
		/**
		 * Parses a prompt type.
		 *
		 * @param s The string to parse.
		 *
		 * @return The prompt type.
		 *
		 * @throws ParseException If the parsed string is {@code null} 
		 *                        or doesn't match a prompt type.
		 */
		public static Type parse(final String s)
			throws ParseException {

			if (StringUtils.isBlank(s))
				throw new ParseException("Null or empty prompt type string");

			switch (s) {
				case "none":
					return NONE;
				case "login":
					return LOGIN;
				case "consent":
					return CONSENT;
				case "select_account":
					return SELECT_ACCOUNT;
				default:
					throw new ParseException("Unknown prompt type: " + s);
			}
		}
	}
	
	
	/**
	 * Creates a new empty prompt.
	 */
	public Prompt() {
	
		// Nothing to do
	}


	/**
	 * Creates a new prompt with the specified types.
	 *
	 * @param type The prompt types.
	 */
	public Prompt(final Type ... type) {

		addAll(Arrays.asList(type));
	}


	/**
	 * Creates a new prompt with the specified type values.
	 *
	 * @param values The prompt type values.
	 *
	 * @throws java.lang.IllegalArgumentException If the type value is
	 *                                            invalid.
	 */
	public Prompt(final String ... values) {

		for (String v: values) {

			try {
				add(Type.parse(v));

			} catch (ParseException e) {

				throw new IllegalArgumentException(e.getMessage(), e);
			}
		}
	}
	
	
	/**
	 * Checks if the prompt is valid. This is done by examining the prompt
	 * for a conflicting {@link Type#NONE} value.
	 *
	 * @return {@code true} if this prompt if valid, else {@code false}.
	 */
	public boolean isValid() {

		return !(size() > 1 && contains(Type.NONE));
	}
	
	
	/**
	 * Returns the string list representation of this prompt.
	 * 
	 * @return The string list representation.
	 */
	public List<String> toStringList() {
		
		List<String> list = new ArrayList<>(this.size());
		
		for (Type t: this)
			list.add(t.toString());
		
		return list;
	}
	
	
	/**
	 * Returns the string representation of this prompt. The values are 
	 * delimited by space.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * login consent
	 * </pre>
	 *
	 * @return The string representation.
	 */
	@Override
	public String toString() {
	
		StringBuilder sb = new StringBuilder();
	
		Iterator<Type> it = super.iterator();
		
		while (it.hasNext()) {
		
			sb.append(it.next().toString());
			
			if (it.hasNext())
				sb.append(" ");
		}
	
		return sb.toString();
	}
	
	
	/**
	 * Parses a prompt from the specified string list.
	 * 
	 * @param collection The string list to parse, with one or more
	 *                   non-conflicting prompt types. May be {@code null}.
	 *
	 * @return The prompt, {@code null} if the parsed string list was
	 *         {@code null} or empty.
	 * 
	 * @throws ParseException If the string list couldn't be parsed to a
	 *                        valid prompt.
	 */
	public static Prompt parse(final Collection<String> collection)
		throws ParseException {
		
		if (collection == null)
			return null;
		
		Prompt prompt = new Prompt();
		
		for (String s: collection)
			prompt.add(Prompt.Type.parse(s));
		
		if (! prompt.isValid())
			throw new ParseException("Invalid prompt: " + collection);
		
		return prompt;	
	}
	
	
	/**
	 * Parses a prompt from the specified string.
	 *
	 * @param s The string to parse, with one or more non-conflicting space
	 *          delimited prompt types. May be {@code null}.
	 *
	 * @return The prompt, {@code null} if the parsed string was 
	 *         {@code null} or empty.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid
	 *                        prompt.
	 */
	public static Prompt parse(final String s)
		throws ParseException {
	
		if (StringUtils.isBlank(s))
			return null;
	
		Prompt prompt = new Prompt();
		
		StringTokenizer st = new StringTokenizer(s, " ");

		while (st.hasMoreTokens())
			prompt.add(Prompt.Type.parse(st.nextToken()));
		
		if (! prompt.isValid())
			throw new ParseException("Invalid prompt: " + s);
		
		return prompt;
	}
}
