package com.nimbusds.openid.connect.sdk.claims;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Authentication Context Class Reference ({@code acr}). It identifies the 
 * authentication context, i.e. the information that the relying party may 
 * require before it makes an entitlements decision with respect to an 
 * authentication response. Such context may include, but is not limited to, 
 * the actual authentication method used or level of assurance such as 
 * ITU-T X.1254 | ISO/IEC 29115 entity authentication assurance level.
 *
 * <p>The ACR is represented by a string or an URL string. This class is 
 * immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.1.
 *     <li>See ISO/IEC DIS 29115
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-21)
 */
@Immutable
public final class ACR extends Identifier {


	/**
	 * ACR level 0.
	 */
	public static final ACR LEVEL_ZERO = new ACR("0");


	/**
	 * ACR level 1.
	 */
	public static final ACR LEVEL_ONE = new ACR("1");


	/**
	 * ACR level 2.
	 */
	public static final ACR LEVEL_TWO = new ACR("2");


	/**
	 * ACR level 3.
	 */
	public static final ACR LEVEL_THREE = new ACR("3");


	/**
	 * ACR level 4.
	 */
	public static final ACR LEVEL_FOUR = new ACR("4");
	
	
	/**
	 * Creates a new Authentication Context Class Reference (ACR) with the
	 * specified value.
	 *
	 * @param value The ACR value. Must not be {@code null}.
	 */
	public ACR(final String value) {
	
		super(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof ACR && 
		       this.toString().equals(object.toString());
	}
}
