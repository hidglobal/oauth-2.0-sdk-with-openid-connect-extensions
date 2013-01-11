package com.nimbusds.openid.connect.sdk.claims;


/**
 * OAuth 2.0 client identifier ({@code client_id}).
 *
 * <p>The client identifier can be a URL or an arbitrary string.
 *
 * <p>See also {@link AuthorizedParty}, {@link Issuer}, {@link Subject} and
 * {@link Audience}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0
 *     <li>OAuth 2.0 (RFC 6749), section 2.2.
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
