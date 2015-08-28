package com.nimbusds.oauth2.sdk.token;


import java.util.Set;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Access and optional refresh token.
 */
@Immutable
public class Tokens {


	/**
	 * Access token.
	 */
	private final AccessToken accessToken;


	/**
	 * Refresh token, {@code null} if not specified.
	 */
	private final RefreshToken refreshToken;


	/**
	 * Creates a new tokens instance.
	 *
	 * @param accessToken  The access token. Must not be {@code null}.
	 * @param refreshToken The refresh token. If none {@code null}.
	 */
	public Tokens(final AccessToken accessToken, final RefreshToken refreshToken) {

		if (accessToken == null)
			throw new IllegalArgumentException("The access token must not be null");

		this.accessToken = accessToken;

		this.refreshToken = refreshToken;
	}
	

	/**
	 * Returns the access token.
	 *
	 * @return The access token.
	 */
	public AccessToken getAccessToken() {

		return accessToken;
	}


	/**
	 * Returns the access token as type bearer.
	 *
	 * @return The bearer access token, {@code null} if the type is
	 *         different.
	 */
	public BearerAccessToken getBearerAccessToken() {

		if (accessToken instanceof BearerAccessToken) {
			return (BearerAccessToken) accessToken;
		}

		return null;
	}


	/**
	 * Returns the optional refresh token.
	 *
	 * @return The refresh token, {@code null} if none.
	 */
	public RefreshToken getRefreshToken() {

		return refreshToken;
	}


	/**
	 * Returns the token parameter names for the included tokens.
	 *
	 * @return The token parameter names.
	 */
	public Set<String> getParameterNames() {

		// Get the std param names for the access + refresh token
		Set<String> paramNames = accessToken.getParameterNames();

		if (refreshToken != null)
			paramNames.addAll(refreshToken.getParameterNames());

		return paramNames;
	}


	/**
	 * Returns the JSON object representation of this token pair.
	 *
	 * <p>Example JSON object:
	 *
	 * <pre>
	 * {
	 *   "access_token"  : "dZdt8BlltORMTz5U",
	 *   "refresh_token" : "E87zjAoeNXaSoF1U"
	 * }
	 * </pre>
	 *
	 * @return The JSON object representation.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = accessToken.toJSONObject();

		if (refreshToken != null)
			o.putAll(refreshToken.toJSONObject());

		return o;
	}


	@Override
	public String toString() {

		return toJSONObject().toJSONString();
	}


	/**
	 * Parses an access and optional refresh token from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The tokens.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        tokens instance.
	 */
	public static Tokens parse(final JSONObject jsonObject)
		throws ParseException {

		return new Tokens(AccessToken.parse(jsonObject), RefreshToken.parse(jsonObject));
	}
}
