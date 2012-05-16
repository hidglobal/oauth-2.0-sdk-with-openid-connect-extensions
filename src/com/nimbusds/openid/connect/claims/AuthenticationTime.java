package com.nimbusds.openid.connect.claims;


/**
 * Authentication time claim. The value is number of seconds from 
 * 1970-01-01T0:0:0Z as measured in UTC until the desired date/time.
 *
 * <p>This claim semantically corresponds to the OpenID 2.0 PAPE 
 * {@code auth_time} response parameter.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-14)
 */
public class AuthenticationTime extends TimeClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "auth_time".
	 */
	public String getClaimName() {
	
		return "auth_time";
	}
}
