package com.nimbusds.openid.connect.claims;


import java.net.URL;


/**
 * Issuer identifier.
 *
 * <p>The issuer identifier may be a URL or an arbitrary string.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.1 and 2.2.1.
 *     <li>draft-jones-oauth-jwt-bearer-04, section 3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-05)
 */
public class Issuer extends StringClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "iss".
	 */
	public String getClaimName() {
	
		return "iss";
	}
}
