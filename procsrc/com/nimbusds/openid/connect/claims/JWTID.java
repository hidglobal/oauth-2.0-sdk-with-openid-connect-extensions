package com.nimbusds.openid.connect.claims;


/**
 * JSON Web Token (JWT) identifier (ID).
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-05-05)
 */
public class JWTID extends StringClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "jti".
	 */
	public String getClaimName() {
	
		return "jti";
	}
}
