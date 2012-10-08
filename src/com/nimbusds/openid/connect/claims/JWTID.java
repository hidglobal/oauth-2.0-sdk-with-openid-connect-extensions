package com.nimbusds.openid.connect.claims;


/**
 * JSON Web Token (JWT) identifier ({@code jti}).
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.2.1.
 *     <li>draft-ietf-oauth-jwt-bearer-02, section 3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-08)
 */
public class JWTID extends StringClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "jti".
	 */
	@Override
	public String getClaimName() {
	
		return "jti";
	}
}
