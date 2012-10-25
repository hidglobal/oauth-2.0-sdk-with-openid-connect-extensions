package com.nimbusds.openid.connect.sdk.claims;


/**
 * Code hash ({@code c_hash}).
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
public class CodeHash extends StringClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "c_hash".
	 */
	@Override
	public String getClaimName() {
	
		return "c_hash";
	}
}
