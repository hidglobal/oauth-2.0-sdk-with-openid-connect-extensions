package com.nimbusds.openid.connect.claims;


/**
 * Code hash.
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
