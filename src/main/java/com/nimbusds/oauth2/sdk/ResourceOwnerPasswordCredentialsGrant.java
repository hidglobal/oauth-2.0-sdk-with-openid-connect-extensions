package com.nimbusds.oauth2.sdk;


import java.util.LinkedHashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.auth.Secret;


/**
 * Resource owner password credentials grant. Used in access token requests
 * with the resource owner's username and password.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 4.3.2.
 * </ul>
 */
@Immutable
public class ResourceOwnerPasswordCredentialsGrant extends AuthorizationGrant {


	/**
	 * The grant type.
	 */
	public static final GrantType GRANT_TYPE = GrantType.PASSWORD;


	/**
	 * The username.
	 */
	private final String username;


	/**
	 * The password.
	 */
	private final Secret password;


	/**
	 * Creates a new resource owner password credentials grant.
	 *
	 * @param username The resource owner's username. Must not be
	 *                 {@code null}.
	 * @param password The resource owner's password. Must not be
	 *                 {@code null}.
	 */
	public ResourceOwnerPasswordCredentialsGrant(final String username,
						     final Secret password) {

		super(GRANT_TYPE);

		if (username == null)
			throw new IllegalArgumentException("The username must not be null");

		this.username = username;

		if (password == null)
			throw new IllegalArgumentException("The password must not be null");

		this.password = password;
	}


	/**
	 * Gets the resource owner's username.
	 *
	 * @return The username.
	 */
	public String getUsername() {

		return username;
	}


	/**
	 * Gets the resource owner's password.
	 *
	 * @return The password.
	 */
	public Secret getPassword() {

		return password;
	}


	@Override
	public Map<String,String> toParameters() {

		Map<String,String> params = new LinkedHashMap<>();
		params.put("grant_type", GRANT_TYPE.getValue());
		params.put("username", username);
		params.put("password", password.getValue());
		return params;
	}


	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		ResourceOwnerPasswordCredentialsGrant that = (ResourceOwnerPasswordCredentialsGrant) o;
		if (!username.equals(that.username)) return false;
		return password.equals(that.password);
	}


	@Override
	public int hashCode() {
		int result = username.hashCode();
		result = 31 * result + password.hashCode();
		return result;
	}


	/**
	 * Parses a resource owner password credentials grant from the
	 * specified parameters.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * grant_type=password
	 * username=johndoe
	 * password=A3ddj3w
	 * </pre>
	 *
	 * @param params The parameters.
	 *
	 * @return The resource owner password credentials grant.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ResourceOwnerPasswordCredentialsGrant parse(final Map<String,String> params)
		throws ParseException {

		// Parse grant type
		String grantTypeString = params.get("grant_type");

		if (grantTypeString == null)
			throw new ParseException("Missing \"grant_type\" parameter", OAuth2Error.INVALID_REQUEST);

		if (! GrantType.parse(grantTypeString).equals(GRANT_TYPE))
			throw new ParseException("The \"grant_type\" must be " + GRANT_TYPE, OAuth2Error.UNSUPPORTED_GRANT_TYPE);

		// Parse the username
		String username = params.get("username");

		if (username == null || username.trim().isEmpty())
			throw new ParseException("Missing or empty \"username\" parameter", OAuth2Error.INVALID_REQUEST);

		// Parse the password
		String passwordString = params.get("password");

		if (passwordString == null || passwordString.trim().isEmpty())
			throw new ParseException("Missing or empty \"password\" parameter", OAuth2Error.INVALID_REQUEST);

		Secret password = new Secret(passwordString);

		return new ResourceOwnerPasswordCredentialsGrant(username, password);
	}
}
