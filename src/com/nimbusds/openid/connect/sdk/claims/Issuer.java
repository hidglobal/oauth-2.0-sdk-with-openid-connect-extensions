package com.nimbusds.openid.connect.sdk.claims;


/**
 * Issuer identifier ({@code iss}).
 *
 * <p>The issuer identifier may be a URL or an arbitrary string.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.1 and 2.2.1.
 *     <li>draft-ietf-oauth-jwt-bearer-02, section 3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-08)
 */
public class Issuer extends StringClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "iss".
	 */
	@Override
	public String getClaimName() {
	
		return "iss";
	}
}
