package com.nimbusds.openid.connect.sdk.claims;


/**
 * Intended audience ({@code aud}). This is typically a {@link ClientID client 
 * identifier} or an authorisation server identifier.
 *
 * <p>The client identifier can be a URL or an arbitrary string.
 *
 * <p>See also {@link ClientID}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.1.
 *     <li>draft-ietf-oauth-jwt-bearer-02, section 3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-08)
 */
public class Audience extends StringClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "aud".
	 */
	@Override
	public String getClaimName() {
	
		return "aud";
	}
}
