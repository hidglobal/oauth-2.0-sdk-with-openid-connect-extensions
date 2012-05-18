package com.nimbusds.openid.connect.claims;


/**
 * Code hash.
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
public class CodeHash extends StringClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "c_hash".
	 */
	public String getClaimName() {
	
		return "c_hash";
	}
}
