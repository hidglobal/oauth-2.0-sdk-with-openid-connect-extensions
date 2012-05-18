package com.nimbusds.openid.connect.claims;


/**
 * Access token hash.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-14)
 */
public class AccessTokenHash extends StringClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "at_hash".
	 */
	public String getClaimName() {
	
		return "at_hash";
	}
}
