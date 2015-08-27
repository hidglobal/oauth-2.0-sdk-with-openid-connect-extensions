package com.nimbusds.openid.connect.sdk;


import java.util.HashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * OpenID Connect access token response with an optional ID token.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * Cache-Control: no-store
 * Pragma: no-cache
 * 
 * {
 *   "access_token"  : "SlAV32hkKG",
 *   "token_type"    : "Bearer",
 *   "refresh_token" : "8xLOxBtZp8",
 *   "expires_in"    : 3600,
 *   "id_token"      : "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9zZXJ2Z
 *    XIuZXhhbXBsZS5jb20iLCJ1c2VyX2lkIjoiMjQ4Mjg5NzYxMDAxIiwiYXVkIjoic
 *    zZCaGRSa3F0MyIsIm5vbmNlIjoibi0wUzZfV3pBMk1qIiwiZXhwIjoxMzExMjgxO
 *    TcwLCJpYXQiOjEzMTEyODA5NzB9.RgXxzppVvn1EjUiV3LIZ19SyhdyREe_2jJjW
 *    5EC8XjNuJfe7Dte8YxRXxssJ67N8MT9mvOI3HOHm4whNx5FCyemyCGyTLHODCeAr
 *    _id029-4JP0KWySoan1jmT7vbGHhu89-l9MTdaEvu7pNZO7DHGwqnMWRe8hdG7jU
 *    ES4w4ReQTygKwXVVOaiGoeUrv6cZdbyOnpGlRlHaiOsv_xMunNVJtn5dLz-0zZwV
 *    ftKVpFuc1pGaVsyZsOtkT32E4c6MDHeCvIDlR5ESC0ct8BLvGJDB5954MjCR4_X2
 *    GAEHonKw4NF8wTmUFvhslYXmjRNFs21Byjn3jNb7lSa3MBfVsw"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 3.1.3.3.
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.4 and 5.1.
 * </ul>
 */
@Immutable
public class OIDCAccessTokenResponse
	extends AccessTokenResponse {


	/**
	 * Optional ID Token serialised to a JWT.
	 */
	private final JWT idToken;


	/**
	 * Optional ID Token as raw string (for more efficient serialisation).
	 */
	private final String idTokenString;


	/**
	 * Creates a new OpenID Connect access token response with no ID token.
	 *
	 * @param accessToken  The access token. Must not be {@code null}.
	 * @param refreshToken Optional refresh token, {@code null} if none.
	 */
	public OIDCAccessTokenResponse(final AccessToken accessToken,
				       final RefreshToken refreshToken) {

		this(accessToken, refreshToken, (String)null);
	}


	/**
	 * Creates a new OpenID Connect access token response.
	 *
	 * @param accessToken  The access token. Must not be {@code null}.
	 * @param refreshToken Optional refresh token, {@code null} if none.
	 * @param idToken      The ID token. Must be {@code null} if the
	 *                     request grant type was not 
	 *                     {@link com.nimbusds.oauth2.sdk.GrantType#AUTHORIZATION_CODE}.
	 */
	public OIDCAccessTokenResponse(final AccessToken accessToken,
	                               final RefreshToken refreshToken,
	                               final JWT idToken) {
				   
		this(accessToken, refreshToken, idToken, null);
	}


	/**
	 * Creates a new OpenID Connect access token response.
	 *
	 * @param accessToken  The access token. Must not be {@code null}.
	 * @param refreshToken Optional refresh token, {@code null} if none.
	 * @param idToken      The ID token. Must be {@code null} if the
	 *                     request grant type was not
	 *                     {@link com.nimbusds.oauth2.sdk.GrantType#AUTHORIZATION_CODE}.
	 * @param customParams Optional custom parameters, {@code null} if
	 *                     none.
	 */
	public OIDCAccessTokenResponse(final AccessToken accessToken,
	                               final RefreshToken refreshToken,
	                               final JWT idToken,
				       final Map<String,Object> customParams) {

		super(accessToken, refreshToken, customParams);

		this.idToken = idToken;

		idTokenString = null;
	}


	/**
	 * Creates a new OpenID Connect access token response.
	 *
	 * @param accessToken   The access token. Must not be {@code null}.
	 * @param refreshToken  Optional refresh token, {@code null} if none.
	 * @param idTokenString The ID token string. Must be {@code null} if
	 *                      the request grant type was not
	 *                      {@link com.nimbusds.oauth2.sdk.GrantType#AUTHORIZATION_CODE}.
	 */
	public OIDCAccessTokenResponse(final AccessToken accessToken,
				       final RefreshToken refreshToken,
				       final String idTokenString) {

		this(accessToken, refreshToken, idTokenString, null);
	}


	/**
	 * Creates a new OpenID Connect access token response.
	 *
	 * @param accessToken   The access token. Must not be {@code null}.
	 * @param refreshToken  Optional refresh token, {@code null} if none.
	 * @param idTokenString The ID token string. Must be {@code null} if
	 *                      the request grant type was not
	 *                      {@link com.nimbusds.oauth2.sdk.GrantType#AUTHORIZATION_CODE}.
	 * @param customParams Optional custom parameters, {@code null} if
	 *                     none.
	 */
	public OIDCAccessTokenResponse(final AccessToken accessToken,
				       final RefreshToken refreshToken,
				       final String idTokenString,
				       final Map<String,Object> customParams) {

		super(accessToken, refreshToken, customParams);

		idToken = null;

		this.idTokenString = idTokenString;
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
	
	
	/**
	 * Returns the JSON object representing this OpenID Connect access 
	 * token response.
	 *
	 * <p>Example JSON object:
	 *
	 * <pre>
	 * {
	 *   "access_token" : "SlAV32hkKG",
	 *   "token_type"   : "Bearer",
	 *   "refresh_token": "8xLOxBtZp8",
	 *   "expires_in"   : 3600,
	 *   "id_token"     : "eyJ0 ... NiJ9.eyJ1c ... I6IjIifX0.DeWt4Qu ... ZXso"
	 * }
	 * </pre>
	 *
	 * @return The JSON object.
	 */
	@Override
	public JSONObject toJSONObject() {
	
		JSONObject o = super.toJSONObject();

		String idTokenOut = getIDTokenString();

		if (idTokenOut != null)
			o.put("id_token", idTokenOut);
		
		return o;
	}
	
	
	/**
	 * Parses an OpenID Connect access token response from the specified 
	 * JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The OpenID Connect access token response.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Connect access token response.
	 */
	public static OIDCAccessTokenResponse parse(final JSONObject jsonObject)
		throws ParseException {
		
		AccessTokenResponse atr = AccessTokenResponse.parse(jsonObject);
		
		JWT idToken = null;
		
		if (jsonObject.containsKey("id_token")) {
			
			try {
				idToken = JWTParser.parse(JSONObjectUtils.getString(jsonObject, "id_token"));
				
			} catch (java.text.ParseException e) {
			
				throw new ParseException("Couldn't parse ID token: " + e.getMessage(), e);
			}
		}

		// Parse the custom parameters
		Map<String,Object> customParams = new HashMap<>();
		customParams.putAll(atr.getCustomParams());
		customParams.remove("id_token");
		
		return new OIDCAccessTokenResponse(atr.getAccessToken(),
			                           atr.getRefreshToken(),
			                           idToken,
			                           customParams);
	}
	
	
	/**
	 * Parses an OpenID Connect access token response from the specified 
	 * HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The OpenID Connect access token response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        OpenID Connect access token response.
	 */
	public static OIDCAccessTokenResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		
		JSONObject jsonObject = httpResponse.getContentAsJSONObject();
		
		return parse(jsonObject);
	}
}
