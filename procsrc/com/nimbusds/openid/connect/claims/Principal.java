package com.nimbusds.openid.connect.claims;


/**
 * Principal. This is typically a {@link ClientID client identifier}.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-05-05)
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
