package com.nimbusds.openid.connect.sdk.claims;


/**
 * Authentication Context Class Reference ({@code acr}). It identifies the 
 * authentication context, i.e. the information that the relying party may 
 * require before it makes an entitlements decision with respect to an 
 * authentication response. Such context may include, but is not limited to, 
 * the actual authentication method used or level of assurance such as 
 * ITU-T X.1254 | ISO/IEC 29115 entity authentication assurance level.
 *
 * <p>The ACR is represented by a string or an URL string.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.1.1.
 *     <li>See ISO/IEC DIS 29115
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-17)
 */
public class ACR extends StringClaim {


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
	 * Creates a new unspecified Authentication Context Class Reference 
	 * (ACR).
	 */
	public ACR() {
	
		super();
	}
	
	
	/**
	 * Creates a new Authentication Context Class Reference (ACR) with the
	 * specified value.
	 *
	 * @param value The ACR value. Must not be {@code null}.
	 */
	private ACR(final String value) {
	
		super();
		
		super.setClaimValue(value);
	}
	
	
	/**
	 * @inheritDoc
	 *
	 * @return "acr".
	 */
	@Override
	public String getClaimName() {
	
		return "acr";
	}
}
