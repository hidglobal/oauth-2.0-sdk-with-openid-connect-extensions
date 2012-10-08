package com.nimbusds.openid.connect.claims;


/**
 * Issue time ({@code iat}). The value is number of seconds from 
 * 1970-01-01T0:0:0Z as measured in UTC until the desired date/time.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.1.
 *     <li>draft-ietf-oauth-jwt-bearer-02, section 3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-08)
 */
public class IssueTime extends TimeClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "iat".
	 */
	@Override
	public String getClaimName() {
	
		return "iat";
	}
}
