package com.nimbusds.oauth2.sdk.auth;


import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.util.Base64;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;


/**
 * Client secret basic authentication at the Token endpoint. Implements
 * {@link ClientAuthenticationMethod#CLIENT_SECRET_BASIC}.
 *
 * <p>Example HTTP Authorization header (for client identifier "s6BhdRkqt3" and
 * secret "7Fjfp0ZBr1KtDRbnfVdmIw"):
 *
 * <pre>
 * Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 2.3.1.
 *     <li>HTTP Authentication: Basic and Digest Access Authentication 
 *         (RFC 2617).
 * </ul>
 */
@Immutable
public final class ClientSecretBasic extends ClientAuthentication {


	/**
	 * The default character set for the client ID and secret encoding.
	 */
	private static final Charset UTF8_CHARSET = Charset.forName("UTF-8");
	
	
	/**
	 * The client secret.
	 */
	private final Secret secret;
	
	
	/**
	 * Creates a new client secret basic authentication.
	 *
	 * @param clientID The client identifier. Must not be {@code null}.
	 * @param secret   The client secret. Must not be {@code null}.
	 */
	public ClientSecretBasic(final ClientID clientID, final Secret secret) {
	
		super(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, clientID);
		
		if (secret == null)
			throw new IllegalArgumentException("The client secret must not be null");
		
		this.secret = secret;
	}
	
	
	/**
	 * Gets the client secret.
	 *
	 * @return The client secret.
	 */
	public Secret getClientSecret() {
	
		return secret;
	}
	
	
	/**
	 * Returns the HTTP Authorization header representation of this client
	 * secret basic authentication.
	 *
	 * <p>Note that OAuth 2.0 (RFC 6749, section 2.3.1) requires the client
	 * ID and secret to be {@code application/x-www-form-urlencoded} before
	 * passing them to the HTTP basic authentication algorithm. This
	 * behaviour differs from the original HTTP Basic Authentication
	 * specification (RFC 2617).
	 *
	 * <p>Example HTTP Authorization header (for client identifier
	 * "Aladdin" and password "open sesame"):
	 *
	 * <pre>
	 *
	 * Authorization: Basic QWxhZGRpbjpvcGVuK3Nlc2FtZQ==
	 * </pre>
	 *
	 * <p>See RFC 2617, section 2.
	 *
	 * @return The HTTP Authorization header.
	 */
	public String toHTTPAuthorizationHeader() {

		StringBuilder sb = new StringBuilder();

		try {
			sb.append(URLEncoder.encode(getClientID().getValue(), UTF8_CHARSET.name()));
			sb.append(':');
			sb.append(URLEncoder.encode(secret.getValue(), UTF8_CHARSET.name()));

		} catch (UnsupportedEncodingException e) {

			// UTF-8 should always be supported
		}

		return "Basic " + Base64.encode(sb.toString().getBytes(UTF8_CHARSET));
	}
	
	
	@Override
	public void applyTo(final HTTPRequest httpRequest) {
	
		httpRequest.setAuthorization(toHTTPAuthorizationHeader());
	}
	
	
	/**
	 * Parses a client secret basic authentication from the specified HTTP
	 * Authorization header.
	 *
	 * @param header The HTTP Authorization header to parse. Must not be 
	 *               {@code null}.
	 *
	 * @return The client secret basic authentication.
	 *
	 * @throws ParseException If the header couldn't be parsed to a client
	 *                        secret basic authentication.
	 */
	public static ClientSecretBasic parse(final String header)
		throws ParseException {
		
		String[] parts = header.split("\\s");
		
		if (parts.length != 2)
			throw new ParseException("Unexpected number of HTTP Authorization header value parts: " + parts.length);
		
		if (! parts[0].equalsIgnoreCase("Basic"))
			throw new ParseException("HTTP authentication must be \"Basic\"");
		
		String credentialsString = new String(new Base64(parts[1]).decode(), UTF8_CHARSET);

		String[] credentials = credentialsString.split(":", 2);
		
		if (credentials.length != 2)
			throw new ParseException("Missing credentials delimiter \":\"");

		try {
			String decodedClientID = URLDecoder.decode(credentials[0], UTF8_CHARSET.name());
			String decodedSecret = URLDecoder.decode(credentials[1], UTF8_CHARSET.name());

			return new ClientSecretBasic(new ClientID(decodedClientID), new Secret(decodedSecret));
			
		} catch (UnsupportedEncodingException e) {
		
			throw new ParseException(e.getMessage(), e);
		}
	}
	
	
	/**
	 * Parses a client secret basic authentication from the specified HTTP
	 * request.
	 *
	 * @param httpRequest The HTTP request to parse. Must not be 
	 *                    {@code null} and must contain a valid 
	 *                    Authorization header.
	 *
	 * @return The client secret basic authentication.
	 *
	 * @throws ParseException If the HTTP Authorization header couldn't be 
	 *                        parsed to a client secret basic 
	 *                        authentication.
	 */
	public static ClientSecretBasic parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		String header = httpRequest.getAuthorization();
		
		if (header == null)
			throw new ParseException("Missing HTTP Authorization header");
			
		return parse(header);
	}
}
