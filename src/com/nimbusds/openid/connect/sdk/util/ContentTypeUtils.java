package com.nimbusds.openid.connect.sdk.util;


import javax.mail.internet.ContentType;

import com.nimbusds.openid.connect.sdk.ParseException;


/**
 * Content type matching.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-11)
 */
public class ContentTypeUtils {


	/**
	 * Ensures the content type of an HTTP header matches an expected value. 
	 * Note that this method compares only the primary type and subtype; any 
	 * content type parameters, such as {@code charset}, are ignored.
	 *
	 * @param expected The expected content type. Must not be {@code null}.
	 * @param found    The found content type. May be {@code null}.
	 *
	 * @throws ParseException If the found content type is {@code null} or
	 *                        it primary and subtype and doesn't match the
	 *                        expected.
	 */
	public static void ensureContentType(final ContentType expected, final ContentType found)
		throws ParseException {
	
		if (found == null)
			throw new ParseException("Missing HTTP Content-Type header");
		
		if (! expected.match(found))
			throw new ParseException("The HTTP Content-Type header must be " + expected);
	}
	

	/**
	 * Prevents instantiation.
	 */
	private ContentTypeUtils() {
	
		// do nothing
	}
}
