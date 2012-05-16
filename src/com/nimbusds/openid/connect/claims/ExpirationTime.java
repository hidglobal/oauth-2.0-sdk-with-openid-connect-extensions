package com.nimbusds.openid.connect.claims;


/**
 * Expiration time claim. The value is number of seconds from 1970-01-01T0:0:0Z 
 * as measured in UTC until the desired date/time.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-14)
 */
public class ExpirationTime extends TimeClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "exp".
	 */
	public String getClaimName() {
	
		return "exp";
	}
}
