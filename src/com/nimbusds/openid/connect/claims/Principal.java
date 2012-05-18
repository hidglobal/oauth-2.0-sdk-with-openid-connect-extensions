package com.nimbusds.openid.connect.claims;


/**
 * Principal. This is typically a {@link ClientID client identifier}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.2.1.
 *     <li>draft-jones-oauth-jwt-bearer-04, section 3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-05)
 */
public class Principal extends StringClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "prn".
	 */
	public String getClaimName() {
	
		return "prn";
	}
}
