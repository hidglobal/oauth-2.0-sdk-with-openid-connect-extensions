package com.nimbusds.openid.connect.util;


/**
 * String utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-10)
 */
public class StringUtils {


	/**
	 * Returns {@code true} if the specified string is not {@code null} and
	 * contains non-whitespace characters.
	 *
	 * @param s The string to check. May be {@code null}.
	 *
	 * @return {@code true} if the string is not {@code null} and contains
	 *         non-whitespace characters, else {@code false}.
	 */
	public static boolean isDefined(final String s) {
	
		if (s == null || s.trim().isEmpty())
			return false;
		else
			return true;
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private StringUtils() {
	
		// Nothing to do
	}
}
