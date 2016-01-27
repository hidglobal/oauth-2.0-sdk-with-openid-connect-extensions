package com.nimbusds.oauth2.sdk;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import net.jcip.annotations.Immutable;
import org.apache.commons.lang.StringUtils;


/**
 * Authorisation code grant. Used in access token requests with an
 * authorisation code.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 4.1.3.
 *     <li>Proof Key for Code Exchange by OAuth Public Clients (RFC 7636).
 * </ul>
 */
@Immutable
public class AuthorizationCodeGrant extends AuthorizationGrant {


	/**
	 * The grant type.
	 */
	public static final GrantType GRANT_TYPE = GrantType.AUTHORIZATION_CODE;


	/**
	 * The authorisation code received from the authorisation server.
	 */
	private final AuthorizationCode code;


	/**
	 * The conditionally required redirection URI in the initial
	 * authorisation request.
	 */
	private final URI redirectURI;


	/**
	 * The optional authorisation code verifier for PKCE.
	 */
	private final CodeVerifier codeVerifier;


	/**
	 * Creates a new authorisation code grant.
	 *
	 * @param code        The authorisation code. Must not be {@code null}.
	 * @param redirectURI The redirection URI of the original authorisation
	 *                    request. Required if the {redirect_uri}
	 *                    parameter was included in the authorisation
	 *                    request, else {@code null}.
	 */
	public AuthorizationCodeGrant(final AuthorizationCode code,
				      final URI redirectURI) {

		this(code, redirectURI, null);
	}


	/**
	 * Creates a new authorisation code grant.
	 *
	 * @param code         The authorisation code. Must not be {@code null}.
	 * @param redirectURI  The redirection URI of the original
	 *                     authorisation request. Required if the
	 *                     {redirect_uri} parameter was included in the
	 *                     authorisation request, else {@code null}.
	 * @param codeVerifier The authorisation code verifier for PKCE,
	 *                     {@code null} if not specified.
	 */
	public AuthorizationCodeGrant(final AuthorizationCode code,
				      final URI redirectURI,
				      final CodeVerifier codeVerifier) {

		super(GRANT_TYPE);

		if (code == null)
			throw new IllegalArgumentException("The authorisation code must not be null");

		this.code = code;

		this.redirectURI = redirectURI;

		this.codeVerifier = codeVerifier;
	}


	/**
	 * Gets the authorisation code.
	 *
	 * @return The authorisation code.
	 */
	public AuthorizationCode getAuthorizationCode() {

		return code;
	}


	/**
	 * Gets the redirection URI of the original authorisation request.
	 *
	 * @return The redirection URI, {@code null} if the
	 *         {@code redirect_uri} parameter was not included in the
	 *         original authorisation request.
	 */
	public URI getRedirectionURI() {

		return redirectURI;
	}


	/**
	 * Gets the authorisation code verifier for PKCE.
	 *
	 * @return The authorisation code verifier, {@code null} if not
	 *         specified.
	 */
	public CodeVerifier getCodeVerifier() {

		return codeVerifier;
	}


	@Override
	public Map<String,String> toParameters() {

		Map<String,String> params = new LinkedHashMap<>();
		params.put("grant_type", GRANT_TYPE.getValue());
		params.put("code", code.getValue());

		if (redirectURI != null)
			params.put("redirect_uri", redirectURI.toString());

		if (codeVerifier != null)
			params.put("code_verifier", codeVerifier.getValue());

		return params;
	}


	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof AuthorizationCodeGrant)) return false;

		AuthorizationCodeGrant codeGrant = (AuthorizationCodeGrant) o;

		if (!code.equals(codeGrant.code)) return false;
		if (redirectURI != null ? !redirectURI.equals(codeGrant.redirectURI) : codeGrant.redirectURI != null)
			return false;
		return codeVerifier != null ? codeVerifier.equals(codeGrant.codeVerifier) : codeGrant.codeVerifier == null;

	}


	@Override
	public int hashCode() {
		int result = code.hashCode();
		result = 31 * result + (redirectURI != null ? redirectURI.hashCode() : 0);
		result = 31 * result + (codeVerifier != null ? codeVerifier.hashCode() : 0);
		return result;
	}


	/**
	 * Parses an authorisation code grant from the specified parameters.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * grant_type=authorization_code
	 * code=SplxlOBeZQQYbYS6WxSbIA
	 * redirect_uri=https://Fclient.example.com/cb
	 * </pre>
	 *
	 * @param params The parameters.
	 *
	 * @return The authorisation code grant.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static AuthorizationCodeGrant parse(final Map<String,String> params)
		throws ParseException {

		// Parse grant type
		String grantTypeString = params.get("grant_type");

		if (grantTypeString == null) {
			String msg = "Missing \"grant_type\" parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
		}

		if (! GrantType.parse(grantTypeString).equals(GRANT_TYPE)) {
			String msg = "The \"grant_type\" must be \"" + GRANT_TYPE + "\"";
			throw new ParseException(msg, OAuth2Error.UNSUPPORTED_GRANT_TYPE.appendDescription(": " + msg));
		}

		// Parse authorisation code
		String codeString = params.get("code");

		if (codeString == null || codeString.trim().isEmpty()) {
			String msg = "Missing or empty \"code\" parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
		}

		AuthorizationCode code = new AuthorizationCode(codeString);

		// Parse optional redirection URI
		String redirectURIString = params.get("redirect_uri");

		URI redirectURI = null;

		if (redirectURIString != null) {
			try {
				redirectURI = new URI(redirectURIString);
			} catch (URISyntaxException e) {
				String msg = "Invalid \"redirect_uri\" parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg), e);
			}
		}


		// Parse optional code verifier
		String codeVerifierString = params.get("code_verifier");

		CodeVerifier codeVerifier = null;

		if (StringUtils.isNotBlank(codeVerifierString)) {

			try {
				codeVerifier = new CodeVerifier(codeVerifierString);
			} catch (IllegalArgumentException e) {
				// Illegal code verifier
				throw new ParseException(e.getMessage(), e);
			}
		}

		return new AuthorizationCodeGrant(code, redirectURI, codeVerifier);
	}
}
