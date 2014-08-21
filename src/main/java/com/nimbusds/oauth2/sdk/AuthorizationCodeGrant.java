package com.nimbusds.oauth2.sdk;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.ClientID;


/**
 * Authorisation code grant. Used in access token requests with an
 * authorisation code.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 4.1.3.
 * </ul>
 */
@Immutable
public final class AuthorizationCodeGrant extends AuthorizationGrant {


	/**
	 * The associated grant type.
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
	 * The conditionally required client ID.
	 */
	private final ClientID clientID;


	/**
	 * Creates a new authorisation code grant. This constructor is
	 * intended for an authenticated access token requests (doesn't require
	 * the client identifier to be specified).
	 *
	 * @param code        The authorisation code. Must not be {@code null}.
	 * @param redirectURI The redirection URI of the original authorisation
	 *                    request. Required if the {redirect_uri}
	 *                    parameter was included in the authorisation
	 *                    request, else {@code null}.
	 */
	public AuthorizationCodeGrant(final AuthorizationCode code,
				      final URI redirectURI) {

		super(GRANT_TYPE);

		if (code == null)
			throw new IllegalArgumentException("The authorisation code must not be null");

		this.code = code;

		this.redirectURI = redirectURI;

		this.clientID = null;
	}


	/**
	 * Creates a new authorisation code grant. This constructor is
	 * intended for an unauthenticated access token request and requires
	 * the client identifier to be specified.
	 *
	 * @param code        The authorisation code. Must not be {@code null}.
	 * @param redirectURI The redirection URI of the original authorisation
	 *                    request, {@code null} if the {@code redirect_uri}
	 *                    parameter was not included in the authorisation
	 *                    request.
	 * @param clientID    The client identifier. Must not be {@code null}.
	 */
	public AuthorizationCodeGrant(final AuthorizationCode code,
				      final URI redirectURI,
				      final ClientID clientID) {

		super(GrantType.AUTHORIZATION_CODE);

		if (code == null)
			throw new IllegalArgumentException("The authorisation code must not be null");

		this.code = code;

		this.redirectURI = redirectURI;

		if (clientID == null)
			throw new IllegalArgumentException("The client identifier must not be null");

		this.clientID = clientID;
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
	 * Gets the client identifier.
	 *
	 * @return The client identifier, {@code null} if not specified
	 *         (implies an authenticated access token request).
	 */
	public ClientID getClientID() {

		return clientID;
	}


	@Override
	public Map<String,String> toParameters() {

		Map<String,String> params = new LinkedHashMap<>();

		params.put("grant_type", GRANT_TYPE.getValue());

		params.put("code", code.getValue());

		if (redirectURI != null)
			params.put("redirect_uri", redirectURI.toString());

		if (clientID != null)
			params.put("client_id", clientID.getValue());

		return params;
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

		if (grantTypeString == null)
			throw new ParseException("Missing \"grant_type\" parameter", OAuth2Error.INVALID_REQUEST);

		GrantType grantType = new GrantType(grantTypeString);

		if (! grantType.equals(GRANT_TYPE))
			throw new ParseException("The \"grant_type\" must be " + GRANT_TYPE, OAuth2Error.UNSUPPORTED_GRANT_TYPE);


		// Parse authorisation code
		String codeString = params.get("code");

		if (codeString == null || codeString.trim().isEmpty())
			throw new ParseException("Missing or empty \"code\" parameter", OAuth2Error.INVALID_REQUEST);

		AuthorizationCode code = new AuthorizationCode(codeString);


		// Parse optional redirection URI
		String redirectURIString = params.get("redirect_uri");

		URI redirectURI = null;

		if (redirectURIString != null) {

			try {
				redirectURI = new URI(redirectURIString);
			} catch (URISyntaxException e) {
				throw new ParseException("Invalid \"redirect_uri\" parameter: " + e.getMessage(), OAuth2Error.INVALID_REQUEST, e);
			}
		}


		// Parse optional client ID
		String clientIDString = params.get("client_id");

		ClientID clientID = null;

		if (clientIDString != null && clientIDString.trim().length() > 0)
			clientID = new ClientID(clientIDString);

		if (clientID == null)
			return new AuthorizationCodeGrant(code, redirectURI);
		else
			return new AuthorizationCodeGrant(code, redirectURI, clientID);
	}
}
