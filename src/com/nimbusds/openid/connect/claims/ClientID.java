package com.nimbusds.openid.connect.claims;


/**
 * OAuth 2.0 client identifier.
 *
 * <p>The client identifier may be a URL or an arbitrary string.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0
 *     <li>draft-ietf-oauth-v2-22, section 2.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-14)
 */
public class ClientID extends StringClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "client_id".
	 */
	public String getClaimName() {
	
		return "client_id";
	}
}
