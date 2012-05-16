package com.nimbusds.openid.connect.messages;


import java.util.HashSet;
import java.util.Iterator;

import com.nimbusds.openid.connect.ParseException;


/**
 * Prompts for end-user reauthentication and consent.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-22)
 */
public class Prompt extends HashSet<Prompt.Type> {


	/**
	 * Enumeration of the prompt types.
	 */
	public static enum Type {
	
	
		/** 
		 * The authorization server must not display any authentication 
		 * or consent UI pages. An error is returned if the end user is 
		 * not already authenticated or the client does not have 
		 * pre-configured consent for the requested scopes. This can be 
		 * used as a method to check for existing authentication and/or 
		 * consent.
		 */
		NONE,


		/**
		 * The authorisation server must prompt the end user for 
		 * reauthentication.
		 */
		LOGIN,


		/**
		 * The authorisation server must prompt the end-user for consent 
		 * before returning information to the client.
		 */
		CONSENT,


		/**
		 * The authorisation server must prompt the end-user to select a 
		 * user account. This allows a user who has multiple accounts at 
		 * the authorization server to select amongst the multiple 
		 * accounts that they may have current sessions for.
		 */
		SELECT_ACCOUNT;
		
		
		/**
		 * Returns the canonical string representation of this prompt
		 * type.
		 *
		 * @return The canonical string representation.
		 */
		public String toString() {
		
			return super.toString().toLowerCase();
		}
		
		
		/**
		 * Parses a prompt type.
		 *
		 * @param s The string to parse.
		 *
		 * @return The parsed prompt type.
		 *
		 * @throws ParseException If the parsed string is {@code null} 
		 *                        or doesn't match a prompt type.
		 */
		public static Type parse(final String s)
			throws ParseException {

			if (s == null || s.trim().isEmpty())
				throw new ParseException("Couldn't parse prompt type: Null or empty value");

			if (s.equals("none"))
				return NONE;

			else if (s.equals("login"))
				return LOGIN;

			else if (s.equals("consent"))
				return CONSENT;

			else if (s.equals("select_account"))
				return SELECT_ACCOUNT;

			else
				throw new ParseException("Couldn't parse prompt type: Unexpected prompt type: " + s);
		}
	}
	
	
	/**
	 * Creates a new empty prompt set.
	 */
	public Prompt() {
	
		// Nothing to do
	}
	
	
	/**
	 * Checks if the prompt set is valid. This is done by examining the set
	 * for a conflicting {@link Type#NONE} value.
	 *
	 * @return {@code true} if this prompt set if valid, else {@code false}.
	 */
	public boolean isValid() {
	
		if (size() > 1 && contains(Type.NONE))
			return false;
		else
			return true;
	}
	
	
	/**
	 * Returns the canonical string representation of this prompt set. The 
	 * values are delimited by space.
	 *
	 * @return The string representation of this scope.
	 */
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
	 * Parses a prompt set from the specified string.
	 *
	 * @param s The string to parse, must contain one or more 
	 *          non-conflicting space-delimited prompt types.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid
	 *                        prompt set.
	 */
	public static Prompt parse(final String s)
		throws ParseException {
	
		Prompt prompt = new Prompt();
		
		String[] tokens = s.split("\\s+");
		
		for (String t: tokens)
			prompt.add(Prompt.Type.parse(t));
		
		if (! prompt.isValid())
			throw new ParseException("Couldn't parse prompt: Invalid set");
		
		return prompt;
	}
}
