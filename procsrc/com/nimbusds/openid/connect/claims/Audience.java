package com.nimbusds.openid.connect.claims;


/**
 * Intended audience. This is typically a {@link ClientID client identifier} or
 * an authorisation server identifier.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-05-05)
 */
public class Audience extends StringClaim {


	/**
	 * @inheritDoc
	 *
	 * @return "aud".
	 */
	public String getClaimName() {
	
		return "aud";
	}
}
