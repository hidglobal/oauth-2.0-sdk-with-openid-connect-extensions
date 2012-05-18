package com.nimbusds.openid.connect.claims;


/**
 * Intended audience. This is typically a {@link ClientID client identifier} or
 * an authorisation server identifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.1.
 *     <li>draft-jones-oauth-jwt-bearer-04, section 3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-05)
 */
public class Audience extends StringClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "aud".
	 */
	public String getClaimName() {
	
		return "aud";
	}
}
