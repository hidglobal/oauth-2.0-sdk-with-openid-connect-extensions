package com.nimbusds.openid.connect.claims;


/**
 * Authentication Context Class Reference ({@code acr}). It identifies the 
 * authentication context, i.e. the information that the relying party may 
 * require before it makes an entitlements decision with respect to an 
 * authentication response. Such context may include, but is not limited to, the 
 * actual authentication method used or level of assurance such as 
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
 * @version $version$ (2012-10-08)
 */
public class AuthenticationContextClassReference extends StringClaim {


	/**
	 * ACR level 0.
	 */
	public static final AuthenticationContextClassReference LEVEL_ZERO = new AuthenticationContextClassReference("0");


	/**
	 * ACR level 1.
	 */
	public static final AuthenticationContextClassReference LEVEL_ONE = new AuthenticationContextClassReference("1");


	/**
	 * ACR level 2.
	 */
	public static final AuthenticationContextClassReference LEVEL_TWO = new AuthenticationContextClassReference("2");


	/**
	 * ACR level 3.
	 */
	public static final AuthenticationContextClassReference LEVEL_THREE = new AuthenticationContextClassReference("3");


	/**
	 * ACR level 4.
	 */
	public static final AuthenticationContextClassReference LEVEL_FOUR = new AuthenticationContextClassReference("4");


	/**
	 * Creates a new unspecified Authentication Context Class Reference 
	 * (ACR).
	 */
	public AuthenticationContextClassReference() {
	
		super();
	}
	
	
	/**
	 * Creates a new Authentication Context Class Reference (ACR) with the
	 * specified value.
	 *
	 * @param value The ACR value. Must not be {@code null}.
	 */
	private AuthenticationContextClassReference(final String value) {
	
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
