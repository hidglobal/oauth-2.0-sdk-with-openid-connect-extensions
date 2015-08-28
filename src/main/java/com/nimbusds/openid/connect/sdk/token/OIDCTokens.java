package com.nimbusds.openid.connect.sdk.token;


import java.util.Set;

import com.nimbusds.jwt.JWT;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWTParser;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Access token, ID token and optional refresh token.
 */
@Immutable
public final class OIDCTokens extends Tokens {


	/**
	 * The ID Token serialised to a JWT. If not specified then the
	 * serialised variant.
	 */
	private final JWT idToken;


	/**
	 * The ID Token as raw string (for more efficient serialisation). If
	 * not specified then the unserialised variant.
	 */
	private final String idTokenString;


	/**
	 * Creates a new OpenID Connect tokens instance.
	 *
	 * @param idToken      The ID token. Must not be {@code null}.
	 * @param accessToken  The access token. Must not be {@code null}.
	 * @param refreshToken The refresh token. If none {@code null}.
	 */
	public OIDCTokens(final JWT idToken, final AccessToken accessToken, final RefreshToken refreshToken) {

		super(accessToken, refreshToken);

		if (idToken == null) {
			throw new IllegalArgumentException("The ID token must not be null");
		}

		this.idToken = idToken;
		idTokenString = null;
	}


	/**
	 * Creates a new OpenID Connect tokens instance.
	 *
	 * @param idTokenString The ID token string. Must not be {@code null}.
	 * @param accessToken   The access token. Must not be {@code null}.
	 * @param refreshToken  The refresh token. If none {@code null}.
	 */
	public OIDCTokens(final String idTokenString, final AccessToken accessToken, final RefreshToken refreshToken) {

		super(accessToken, refreshToken);

		if (idTokenString == null) {
			throw new IllegalArgumentException("The ID token string must not be null");
		}

		this.idTokenString = idTokenString;
		idToken = null;
	}


	/**
	 * Gets the ID token.
	 *
	 * @return The ID token, {@code null} if none or if parsing to a JWT
	 *         failed.
	 */
	public JWT getIDToken() {

		if (idToken != null)
			return idToken;

		if (idTokenString != null) {

			try {
				return JWTParser.parse(idTokenString);

			} catch (java.text.ParseException e) {

				return null;
			}
		}

		return null;
	}


	/**
	 * Gets the ID token string.
	 *
	 * @return The ID token string, {@code null} if none or if
	 *         serialisation to a string failed.
	 */
	public String getIDTokenString() {

		if (idTokenString != null)
			return idTokenString;

		if (idToken != null) {

			// Reproduce originally parsed string if any
			if (idToken.getParsedString() != null)
				return idToken.getParsedString();

			try {
				return idToken.serialize();

			} catch(IllegalStateException e) {

				return null;
			}
		}

		return null;
	}


	@Override
	public Set<String> getParameterNames() {

		Set<String> paramNames = super.getParameterNames();
		paramNames.add("id_token");
		return paramNames;
	}


	@Override
	public JSONObject toJSONObject() {

		JSONObject o = super.toJSONObject();
		o.put("id_token", getIDTokenString());
		return o;
	}


	/**
	 * Parses an OpenID Connect tokens instance from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The OpenID Connect tokens.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Connect tokens instance.
	 */
	public static OIDCTokens parse(final JSONObject jsonObject)
		throws ParseException {

		JWT idToken;

		try {
			idToken = JWTParser.parse(JSONObjectUtils.getString(jsonObject, "id_token"));

		} catch (java.text.ParseException e) {

			throw new ParseException("Couldn't parse ID token: " + e.getMessage(), e);
		}

		return new OIDCTokens(idToken, AccessToken.parse(jsonObject), RefreshToken.parse(jsonObject));
	}
}
