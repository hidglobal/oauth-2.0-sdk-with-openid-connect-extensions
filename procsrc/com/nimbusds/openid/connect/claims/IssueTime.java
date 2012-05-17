package com.nimbusds.openid.connect.claims;


/**
 * Issue time claim. The value is number of seconds from 1970-01-01T0:0:0Z as
 * measured in UTC until the desired date/time.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-04-14)
 */
public class IssueTime extends TimeClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "iat".
	 */
	public String getClaimName() {
	
		return "iat";
	}
}
