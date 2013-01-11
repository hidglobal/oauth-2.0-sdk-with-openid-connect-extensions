package com.nimbusds.openid.connect.sdk.claims;


/**
 * OAuth 2.0 client authorized to use the ID Token as an OAuth access token, 
 * if different than the client that requested the ID Token ({@code azp}). It 
 * must contain the {@link ClientID client identifier} of the authorised party.
 *
 * <p>The client identifier can be a URL or an arbitrary string.
 *
 * <p>See also {@link ClientID}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0
 *     <li>OAuth 2.0 (RFC 6749), section 2.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-11)
 */
public class AuthorizedParty extends StringClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "azp".
	 */
	@Override
	public String getClaimName() {
	
		return "azp";
	}
}
