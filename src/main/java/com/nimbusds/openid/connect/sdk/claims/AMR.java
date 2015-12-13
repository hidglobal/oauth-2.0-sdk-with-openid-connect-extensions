package com.nimbusds.openid.connect.sdk.claims;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Authentication Method Reference ({@code amr}). It identifies the method
 * used in authentication.
 *
 * <p>The AMR is represented by a string or an URI string.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 2.
 * </ul>
 */
@Immutable
public final class AMR extends Identifier {


	/**
	 * Retina scan biometric.
	 */
	public static final AMR EYE = new AMR("eye");


	/**
	 * Fingerprint biometric.
	 */
	public static final AMR FPT = new AMR("fpt");


	/**
	 * Knowledge-based authentication (see NIST.800-63-2).
	 */
	public static final AMR KBA = new AMR("kba");


	/**
	 * Multiple-channel authentication. The authentication involves
	 * communication over more than one distinct channel.
	 */
	public static final AMR MCA = new AMR("mca");


	/**
	 * Multiple-factor authentication (see NIST.800-63-2). When this is
	 * present, specific authentication methods used may also be included.
	 */
	public static final AMR MFA = new AMR("mfa");


	/**
	 * One-time password. One-time password specifications that this
	 * authentication method applies to include RFC 4226 and RFC 6238.
	 */
	public static final AMR OTP = new AMR("otp");


	/**
	 * Proof-of-possession (PoP) of a key. See Appendix C of RFC 4211 for a
	 * discussion on PoP.
	 */
	public static final AMR POP = new AMR("pop");


	/**
	 * Password-based authentication.
	 */
	public static final AMR PWD = new AMR("pwd");


	/**
	 * Risk-based authentication. See <a href="http://utica.edu/academic/institutes/ecii/publications/articles/51D6D996-90F2-F468-AC09C4E8071575AE.pdf">Enhanced
	 * Authentication In Online Banking</a>, Journal of Economic Crime
	 * Management 4.2: 18-19, 2006.
	 */
	public static final AMR RBA = new AMR("rba");


	/**
	 * Smart card.
	 */
	public static final AMR SC = new AMR("sc");


	/**
	 * Confirmation by SMS reply.
	 */
	public static final AMR SMS = new AMR("sms");


	/**
	 * Confirmation by telephone call.
	 */
	public static final AMR TEL = new AMR("tel");


	/**
	 * User presence test.
	 */
	public static final AMR USER = new AMR("user");


	/**
	 * Voice biometric.
	 */
	public static final AMR VBM = new AMR("vbm");


	/**
	 * Windows integrated authentication. See
	 * <a href="http://blogs.msdn.com/b/benjaminperkins/archive/2011/09/14/iis-integrated-windows-authentication-with-negotiate.aspx">Integrated
	 * Windows Authentication with Negotiate</a>, September 2011.
	 */
	public static final AMR WIA = new AMR("wia");


	
	/**
	 * Creates a new Authentication Method Reference (AMR) with the
	 * specified value.
	 *
	 * @param value The AMR value. Must not be {@code null}.
	 */
	public AMR(final String value) {

		super(value);
	}


	@Override
	public boolean equals(final Object object) {

		return object instanceof AMR &&
		       this.toString().equals(object.toString());
	}
}
