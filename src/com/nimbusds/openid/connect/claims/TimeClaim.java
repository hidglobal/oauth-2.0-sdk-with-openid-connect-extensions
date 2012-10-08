package com.nimbusds.openid.connect.claims;


import java.util.Date;


/**
 * The base abstract class for time-based claims. The value is number of seconds 
 * from 1970-01-01T0:0:0Z as measured in UTC until the desired date/time.
 *
 * <p>See RFC 3339.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-08)
 */
public abstract class TimeClaim extends LongClaim {
	
	
	/**
	 * Gets the claim value as {@code java.util.Date} instance.
	 *
	 * @return The time claim.
	 */
	public Date getClaimValueAsDate() {
	
		// Convert seconds to milliseconds
		return new Date(super.getClaimValue() * 1000);
	}
	
	
	/**
	 * @inheritDoc
	 *
	 * @param value The value as number of seconds since 1970-01-01T0:0:0Z.
	 *
	 * @throws IllegalArgumentException If the value is {@code null} or 
	 *                                  negative.
	 */
	@Override
	public void setClaimValue(final Long value) {
	
		if (value == null || value < 0)
			throw new IllegalArgumentException("The time value must not be null or negative");
		
		super.setClaimValue(value);
	}
	
	
	/**
	 * Sets the time claim value.
	 *
	 * @param date The date/time. Must not be {@code null}.
	 *
	 * @throws IllegalArgumentException If the value is {@code null}.
	 */
	public void setClaimValue(final Date date) {
	
		if (date == null)
			throw new IllegalArgumentException("The Date object must not be null");
			
		// Convert milliseconds to seconds
		super.setClaimValue(date.getTime() / 1000);
	}
	
	
	/**
	 * Sets the claim value to the current UTC time.
	 */
	public void setNowClaimValue() {
	
		Date now = new Date();
		
		setClaimValue(now);
	}
}
