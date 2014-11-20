package com.nimbusds.oauth2.sdk.client;


import java.net.URI;
import java.util.Date;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Client credentials parser.
 */
public class ClientCredentialsParser {


	/**
	 * Parses a client identifier from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The client identifier.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ClientID parseID(final JSONObject jsonObject)
		throws ParseException {

		return new ClientID(JSONObjectUtils.getString(jsonObject, "client_id"));
	}


	/**
	 * Parses a client identifier issue date from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The client identifier issue date, {@code null} if not
	 *         specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static Date parseIDIssueDate(final JSONObject jsonObject)
		throws ParseException {

		if (jsonObject.containsKey("client_id_issued_at")) {

			return new Date(JSONObjectUtils.getLong(jsonObject, "client_id_issued_at") * 1000);
		} else {
			return null;
		}
	}


	/**
	 * Parses a client secret from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The client secret, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static Secret parseSecret(final JSONObject jsonObject)
		throws ParseException {

		if (jsonObject.containsKey("client_secret")) {

			String value = JSONObjectUtils.getString(jsonObject, "client_secret");

			Date exp = null;

			if (jsonObject.containsKey("client_secret_expires_at")) {

				final long t = JSONObjectUtils.getLong(jsonObject, "client_secret_expires_at");

				if (t > 0) {
					exp = new Date(t * 1000);
				}
			}

			return new Secret(value, exp);
		} else {
			return null;
		}
	}


	/**
	 * Parses a client registration URI from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The client registration URI, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static URI parseRegistrationURI(final JSONObject jsonObject)
		throws ParseException {

		if (jsonObject.containsKey("registration_client_uri")) {

			return JSONObjectUtils.getURI(jsonObject, "registration_client_uri");
		} else {
			return null;
		}
	}


	/**
	 * Parses a client registration access token from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The client registration access token, {@code null} if not
	 *         specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static BearerAccessToken parseRegistrationAccessToken(final JSONObject jsonObject)
		throws ParseException {

		if (jsonObject.containsKey("registration_access_token")) {

			return new BearerAccessToken(
				JSONObjectUtils.getString(jsonObject, "registration_access_token"));
		} else {
			return null;
		}
	}
}
