package com.nimbusds.openid.connect.claims;


/**
 * OAuth 2.0 client identifier.
 *
 * <p>The client identifier may be a URL or an arbitrary string.
 *
 * <p>See http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-2.2
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-04-14)
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
