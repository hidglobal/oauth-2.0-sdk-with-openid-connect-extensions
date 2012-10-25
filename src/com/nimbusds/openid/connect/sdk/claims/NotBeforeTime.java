package com.nimbusds.openid.connect.sdk.claims;


/**
 * Not-before time claim ({@code nbf}). The value is number of seconds from 
 * 1970-01-01T0:0:0Z as measured in UTC until the desired date/time.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>draft-ietf-oauth-jwt-bearer-02, section 3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-08)
 */
public class NotBeforeTime extends TimeClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "nbf".
	 */
	@Override
	public String getClaimName() {
	
		return "nbf";
	}
}
