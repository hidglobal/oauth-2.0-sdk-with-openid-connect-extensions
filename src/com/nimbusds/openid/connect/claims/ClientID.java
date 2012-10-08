package com.nimbusds.openid.connect.claims;


/**
 * OAuth 2.0 client identifier ({@code client_id}).
 *
 * <p>The client identifier may be a URL or an arbitrary string.
 *
 * <p>See also {@link Issuer}, {@link Audience} and {@link Principal}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0
 *     <li>draft-ietf-oauth-v2-31, section 2.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-08)
 */
public class ClientID extends StringClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "client_id".
	 */
	@Override
	public String getClaimName() {
	
		return "client_id";
	}
}
