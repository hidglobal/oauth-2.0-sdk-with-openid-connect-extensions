package com.nimbusds.openid.connect.claims;


/**
 * Principal ({@code prn}). In the context of OpenID Connect this can be a 
 * {@link ClientID client identifier}.
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
public class Principal extends StringClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "prn".
	 */
	@Override
	public String getClaimName() {
	
		return "prn";
	}
}
