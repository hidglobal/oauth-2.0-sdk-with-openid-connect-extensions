package com.nimbusds.oauth2.sdk.util;


import java.util.Date;


/**
 * Date utilities.
 */
public class DateUtils {


	/**
	 * Converts the specified date object to a Unix epoch time in seconds.
	 *
	 * @param date The date. Must not be {@code null}.
	 *
	 * @return The Unix epoch time, in seconds.
	 */
	public static long toSecondsSinceEpoch(final Date date) {

		return date.getTime() / 1000;
	}


	/**
	 * Converts the specified Unix epoch time in seconds to a date object.
	 *
	 * @param time The Unix epoch time, in seconds. Must not be negative.
	 *
	 * @return The date.
	 */
	public static Date fromSecondsSinceEpoch(final long time) {

		return new Date(time * 1000);
	}


	/**
	 * Prevents instantiation.
	 */
	private DateUtils() { }
}
