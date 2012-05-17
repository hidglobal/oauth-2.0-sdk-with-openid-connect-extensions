package com.nimbusds.openid.connect.claims;


import java.net.URL;


/**
 * Issuer identifier.
 *
 * <p>The issuer identifier may be a URL or an arbitrary string.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-05-05)
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
