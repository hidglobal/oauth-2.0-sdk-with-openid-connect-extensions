package com.nimbusds.openid.connect.sdk;


import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * OpenID Connect access token response. This class is immutable.
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
 *     <li>OpenID Connect Messages 1.0, section 2.2.3.
 *     <li>OpenID Connect Standard 1.0, section 3.1.2.
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.4 and 5.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public final class OIDCAccessTokenResponse 
	extends AccessTokenResponse
	implements OIDCTokenResponse {


	/**
	 * Optional ID Token serialised to a JWT.
	 */
	private final JWT idToken;
	
	
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
				   
		super(accessToken, refreshToken);
		
		this.idToken = idToken;
	}
	
	
	/**
	 * Gets the ID token.
	 *
	 * @return The ID token, {@code null} if none.
	 */
	public JWT getIDToken() {
	
		return idToken;
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
	 *
	 * @throws SerializeException If this OpenID Connect access token 
	 *                            response couldn't be serialised to a JSON
	 *                            object.
	 */
	@Override
	public JSONObject toJSONObject()
		throws SerializeException {
	
		JSONObject o = super.toJSONObject();

		if (idToken != null) {
			
			try {
				o.put("id_token", idToken.serialize());

			} catch (IllegalStateException e) {

				throw new SerializeException("Couldn't serialize ID token: " + e.getMessage(), e);
			}
		}
		
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
		
		
		return new OIDCAccessTokenResponse(atr.getAccessToken(),
			                           atr.getRefreshToken(),
			                           idToken);
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
