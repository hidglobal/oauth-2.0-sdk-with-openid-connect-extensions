package com.nimbusds.openid.connect.sdk.claims;


/**
 * Authentication time ({@code auth_time}). The value is number of seconds from
 * 1970-01-01T0:0:0Z as measured in UTC until the desired date/time.
 *
 * <p>This claim semantically corresponds to the OpenID 2.0 PAPE 
 * {@code auth_time} response parameter.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-08)
 */
public class AuthenticationTime extends TimeClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "auth_time".
	 */
	@Override
	public String getClaimName() {
	
		return "auth_time";
	}
}
