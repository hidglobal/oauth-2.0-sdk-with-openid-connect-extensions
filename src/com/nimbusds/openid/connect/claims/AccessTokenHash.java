package com.nimbusds.openid.connect.claims;


/**
 * Access token hash.
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
