package com.nimbusds.openid.connect.claims;


/**
 * JSON Web Token (JWT) identifier (ID).
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.2.1.
 *     <li>draft-jones-oauth-jwt-bearer-04, section 3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-05)
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
