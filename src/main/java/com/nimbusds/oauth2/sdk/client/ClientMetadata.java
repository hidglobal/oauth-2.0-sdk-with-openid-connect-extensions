package com.nimbusds.oauth2.sdk.client;


import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagUtils;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.SoftwareID;
import com.nimbusds.oauth2.sdk.id.SoftwareVersion;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Client metadata.
 * 
 * <p>Example client metadata, serialised to a JSON object:
 * 
 * <pre>
 * {
 *  "redirect_uris"             : ["https://client.example.org/callback",
 *                                 "https://client.example.org/callback2"],
 *  "client_name"                : "My Example Client",
 *  "client_name#ja-Jpan-JP"     : "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
 *  "token_endpoint_auth_method" : "client_secret_basic",
 *  "scope"                      : "read write dolphin",
 *  "logo_uri"                   : "https://client.example.org/logo.png",
 *  "jwks_uri"                   : "https://client.example.org/my_public_keys.jwks"
 * }
 * </pre>
 * 
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol 
 *         (draft-ietf-oauth-dyn-reg-14), section 2.
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 */
public class ClientMetadata {
	
	
	/**
	 * Redirect URIs.
	 */
	private Set<URL> redirectURIs;
	
	
	/**
	 * The client OAuth 2.0 scope.
	 */
	private Scope scope;
	
	
	/**
	 * The expected OAuth 2.0 response types.
	 */
	private Set<ResponseType> responseTypes;
	
	
	/**
	 * The expected OAuth 2.0 grant types.
	 */
	private Set<GrantType> grantTypes;
	
	
	/**
	 * Administrator contacts for the client.
	 */
	private List<InternetAddress> contacts;


	/**
	 * The client name.
	 */
	private Map<LangTag,String> nameEntries;


	/**
	 * The client application logo.
	 */
	private Map<LangTag,URL> logoURIEntries;
	
	
	/**
	 * The client URI entries.
	 */
	private Map<LangTag,URL> uriEntries;


	/**
	 * The client policy for use of end-user data.
	 */
	private Map<LangTag,URL> policyURIEntries;


	/**
	 * The client terms of service.
	 */
	private Map<LangTag,URL> tosURIEntries;
	
	
	/**
	 * Token endpoint authentication method.
	 */
	private ClientAuthenticationMethod authMethod;
	
	
	/**
	 * URI for this client's JSON Web Key (JWK) set containing key(s) that
	 * are used in signing requests to the server and key(s) for encrypting
	 * responses.
	 */
	private URL jwkSetURI;


	/**
	 * Identifier for the OAuth 2.0 client software.
	 */
	private SoftwareID softwareID;


	/**
	 * Version identifier for the OAuth 2.0 client software.
	 */
	private SoftwareVersion softwareVersion;
	
	
	/** 
	 * Creates a new OAuth 2.0 client metadata instance.
	 */
	public ClientMetadata() {

		nameEntries = new HashMap<LangTag,String>();
		logoURIEntries = new HashMap<LangTag,URL>();
		uriEntries = new HashMap<LangTag,URL>();
		policyURIEntries = new HashMap<LangTag,URL>();
		policyURIEntries = new HashMap<LangTag,URL>();
		tosURIEntries = new HashMap<LangTag,URL>();
	}
	
	
	/**
	 * Creates a shallow copy of the specified OAuth 2.0 client metadata
	 * instance.
	 * 
	 * @param metadata The client metadata to copy. Must not be 
	 *                 {@code null}.
	 */
	public ClientMetadata(final ClientMetadata metadata) {
		
		redirectURIs = metadata.redirectURIs;
		scope = metadata.scope;
		responseTypes = metadata.responseTypes;
		grantTypes = metadata.grantTypes;
		contacts = metadata.contacts;
		nameEntries = metadata.nameEntries;
		logoURIEntries = metadata.logoURIEntries;
		uriEntries = metadata.uriEntries;
		policyURIEntries = metadata.policyURIEntries;
		tosURIEntries = metadata.tosURIEntries;
		authMethod = metadata.authMethod;
		jwkSetURI = metadata.jwkSetURI;
	}
	
	
	/**
	 * Gets the redirect URIs for this client. Corresponds to the
	 * {@code redirect_uris} client metadata field.
	 *
	 * @return The redirect URIs, {@code null} if not specified.
	 */
	public Set<URL> getRedirectURIs() {
	
		return redirectURIs;
	}
	
	
	/**
	 * Sets the redirect URIs for this client. Corresponds to the
	 * {@code redirect_uris} client metadata field.
	 *
	 * @param redirectURIs The redirect URIs, {@code null} if not 
	 *                     specified.
	 */
	public void setRedirectURIs(final Set<URL> redirectURIs) {
	
		this.redirectURIs = redirectURIs;
	}
	
	
	/**
	 * Gets the scope values that the client can use when requesting access 
	 * tokens. Corresponds to the {@code scope} client metadata field.
	 * 
	 * @return The scope, {@code null} if not specified.
	 */
	public Scope getScope() {
		
		return scope;
	}
	
	
	/**
	 * Sets the scope values that the client can use when requesting access 
	 * tokens. Corresponds to the {@code scope} client metadata field.
	 * 
	 * @param scope The scope, {@code null} if not specified.
	 */
	public void setScope(final Scope scope) {
		
		this.scope = scope;
	}
	
	
	/**
	 * Gets the expected OAuth 2.0 response types. Corresponds to the
	 * {@code response_types} client metadata field.
	 * 
	 * @return The response types, {@code null} if not specified.
	 */
	public Set<ResponseType> getResponseTypes() {
		
		return responseTypes;
	}
	
	
	/**
	 * Sets the expected OAuth 2.0 response types. Corresponds to the
	 * {@code response_types} client metadata field.
	 * 
	 * @param responseTypes The response types, {@code null} if not 
	 *                      specified.
	 */
	public void setResponseTypes(final Set<ResponseType> responseTypes) {
		
		this.responseTypes = responseTypes;
	}
	
	
	/**
	 * Gets the expected OAuth 2.0 grant types. Corresponds to the
	 * {@code grant_types} client metadata field.
	 * 
	 * @return The grant types, {@code null} if not specified.
	 */
	public Set<GrantType> getGrantTypes() {
		
		return grantTypes;
	}
	
	
	/**
	 * Sets the expected OAuth 2.0 grant types. Corresponds to the
	 * {@code grant_types} client metadata field.
	 * 
	 * @param grantTypes The grant types, {@code null} if not specified.
	 */
	public void setGrantTypes(final Set<GrantType> grantTypes) {
		
		this.grantTypes = grantTypes;
	}
	
	
	/**
	 * Gets the administrator contacts for the client. Corresponds to the
	 * {@code contacts} client metadata field.
	 *
	 * @return The administrator contacts, {@code null} if not specified.
	 */
	public List<InternetAddress> getContacts() {

		return contacts;
	}


	/**
	 * Sets the administrator contacts for the client. Corresponds to the
	 * {@code contacts} client metadata field.
	 *
	 * @param contacts The administrator contacts, {@code null} if not
	 *                 specified.
	 */
	public void setContacts(final List<InternetAddress> contacts) {

		this.contacts = contacts;
	}
	
	
	/**
	 * Gets the client name. Corresponds to the {@code client_name} client 
	 * metadata field, with no language tag.
	 *
	 * @return The client name, {@code null} if not specified.
	 */
	public String getName() {

		return getName(null);
	}


	/**
	 * Gets the client name. Corresponds to the {@code client_name} client
	 * metadata field, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The client name, {@code null} if not specified.
	 */
	public String getName(final LangTag langTag) {

		return nameEntries.get(langTag);
	}


	/**
	 * Gets the client name entries. Corresponds to the {@code client_name}
	 * client metadata field.
	 *
	 * @return The client name entries, empty map if none.
	 */
	public Map<LangTag,String> getNameEntries() {

		return nameEntries;
	}


	/**
	 * Sets the client name. Corresponds to the {@code client_name} client
	 * metadata field, with no language tag.
	 *
	 * @param name The client name, {@code null} if not specified.
	 */
	public void setName(final String name) {

		nameEntries.put(null, name);
	}


	/**
	 * Sets the client name. Corresponds to the {@code client_name} client
	 * metadata field, with an optional language tag.
	 *
	 * @param name    The client name. Must not be {@code null}.
	 * @param langTag The language tag, {@code null} if not specified.
	 */
	public void setName(final String name, final LangTag langTag) {

		nameEntries.put(langTag, name);
	}


	/**
	 * Gets the client application logo. Corresponds to the 
	 * {@code logo_uri} client metadata field, with no language 
	 * tag.
	 *
	 * @return The logo URI, {@code null} if not specified.
	 */
	public URL getLogoURI() {

		return getLogoURI(null);
	}


	/**
	 * Gets the client application logo. Corresponds to the 
	 * {@code logo_uri} client metadata field, with an optional
	 * language tag.
	 *
	 * @return The logo URI, {@code null} if not specified.
	 */
	public URL getLogoURI(final LangTag langTag) {

		return logoURIEntries.get(langTag);
	}


	/**
	 * Gets the client application logo entries. Corresponds to the 
	 * {@code logo_uri} client metadata field.
	 *
	 * @return The logo URI entries, empty map if none.
	 */
	public Map<LangTag,URL> getLogoURIEntries() {

		return logoURIEntries;
	}


	/**
	 * Sets the client application logo. Corresponds to the 
	 * {@code logo_uri} client metadata field, with no language 
	 * tag.
	 *
	 * @param logoURI The logo URI, {@code null} if not specified.
	 */
	public void setLogoURI(final URL logoURI) {

		logoURIEntries.put(null, logoURI);
	}


	/**
	 * Sets the client application logo. Corresponds to the 
	 * {@code logo_uri} client metadata field, with an optional
	 * language tag.
	 *
	 * @param logoURI The logo URI. Must not be {@code null}.
	 * @param langTag The language tag, {@code null} if not specified.
	 */
	public void setLogoURI(final URL logoURI, final LangTag langTag) {

		logoURIEntries.put(langTag, logoURI);
	}
	
	
	/**
	 * Gets the client home page. Corresponds to the {@code client_uri} 
	 * client metadata field, with no language tag.
	 *
	 * @return The client URI, {@code null} if not specified.
	 */
	public URL getURI() {

		return getURI(null);
	}


	/**
	 * Gets the client home page. Corresponds to the {@code client_uri} 
	 * client metadata field, with an optional language tag.
	 *
	 * @return The client URI, {@code null} if not specified.
	 */
	public URL getURI(final LangTag langTag) {

		return uriEntries.get(langTag);
	}


	/**
	 * Gets the client home page entries. Corresponds to the 
	 * {@code client_uri} client metadata field.
	 *
	 * @return The client URI entries, empty map if none.
	 */
	public Map<LangTag,URL> getURIEntries() {

		return uriEntries;
	}


	/**
	 * Sets the client home page. Corresponds to the {@code client_uri} 
	 * client metadata field, with no language tag.
	 *
	 * @param uri The client URI, {@code null} if not specified.
	 */
	public void setURI(final URL uri) {

		uriEntries.put(null, uri);
	}


	/**
	 * Sets the client home page. Corresponds to the {@code client_uri} 
	 * client metadata field, with an optional language tag.
	 *
	 * @param uri     The URI. Must not be {@code null}.
	 * @param langTag The language tag, {@code null} if not specified.
	 */
	public void setURI(final URL uri, final LangTag langTag) {

		uriEntries.put(langTag, uri);
	}
	

	/**
	 * Gets the client policy for use of end-user data. Corresponds to the 
	 * {@code policy_uri} client metadata field, with no language 
	 * tag.
	 *
	 * @return The policy URI, {@code null} if not specified.
	 */
	public URL getPolicyURI() {

		return getPolicyURI(null);
	}


	/**
	 * Gets the client policy for use of end-user data. Corresponds to the 
	 * {@code policy_url} client metadata field, with an optional
	 * language tag.
	 *
	 * @return The policy URI, {@code null} if not specified.
	 */
	public URL getPolicyURI(final LangTag langTag) {

		return policyURIEntries.get(langTag);
	}


	/**
	 * Gets the client policy entries for use of end-user data. 
	 * Corresponds to the {@code policy_uri} client metadata field.
	 *
	 * @return The policy URI entries, empty map if none.
	 */
	public Map<LangTag,URL> getPolicyURIEntries() {

		return policyURIEntries;
	}


	/**
	 * Sets the client policy for use of end-user data. Corresponds to the 
	 * {@code policy_uri} client metadata field, with no language 
	 * tag.
	 *
	 * @param policyURI The policy URI, {@code null} if not specified.
	 */
	public void setPolicyURI(final URL policyURI) {

		policyURIEntries.put(null, policyURI);
	}


	/**
	 * Sets the client policy for use of end-user data. Corresponds to the 
	 * {@code policy_uri} client metadata field, with an optional
	 * language tag.
	 *
	 * @param policyURI The policy URI. Must not be {@code null}.
	 * @param langTag   The language tag, {@code null} if not specified.
	 */
	public void setPolicyURI(final URL policyURI, final LangTag langTag) {

		policyURIEntries.put(langTag, policyURI);
	}


	/**
	 * Gets the client's terms of service. Corresponds to the 
	 * {@code tos_uri} client metadata field, with no language 
	 * tag.
	 *
	 * @return The terms of service URI, {@code null} if not specified.
	 */
	public URL getTermsOfServiceURI() {

		return getTermsOfServiceURI(null);
	}


	/**
	 * Gets the client's terms of service. Corresponds to the 
	 * {@code tos_uri} client metadata field, with an optional
	 * language tag.
	 *
	 * @return The terms of service URI, {@code null} if not specified.
	 */
	public URL getTermsOfServiceURI(final LangTag langTag) {

		return tosURIEntries.get(langTag);
	}


	/**
	 * Gets the client's terms of service entries. Corresponds to the 
	 * {@code tos_uri} client metadata field.
	 *
	 * @return The terms of service URI entries, empty map if none.
	 */
	public Map<LangTag,URL> getTermsOfServiceURIEntries() {

		return tosURIEntries;
	}


	/**
	 * Sets the client's terms of service. Corresponds to the 
	 * {@code tos_uri} client metadata field, with no language 
	 * tag.
	 *
	 * @param tosURI The terms of service URI, {@code null} if not 
	 *               specified.
	 */
	public void setTermsOfServiceURI(final URL tosURI) {

		tosURIEntries.put(null, tosURI);
	}


	/**
	 * Sets the client's terms of service. Corresponds to the 
	 * {@code tos_uri} client metadata field, with an optional
	 * language tag.
	 *
	 * @param tosURI  The terms of service URI. Must not be {@code null}.
	 * @param langTag The language tag, {@code null} if not specified.
	 */
	public void setTermsOfServiceURI(final URL tosURI, final LangTag langTag) {

		tosURIEntries.put(langTag, tosURI);
	}
	
	
	/**
	 * Gets the Token endpoint authentication method. Corresponds to the 
	 * {@code token_endpoint_auth_method} client metadata field.
	 *
	 * @return The Token endpoint authentication method, {@code null} if
	 *         not specified.
	 */
	public ClientAuthenticationMethod getTokenEndpointAuthMethod() {

		return authMethod;
	}


	/**
	 * Sets the Token endpoint authentication method. Corresponds to the 
	 * {@code token_endpoint_auth_method} client metadata field.
	 *
	 * @param authMethod The Token endpoint authentication  method, 
	 *                   {@code null} if not specified.
	 */
	public void setTokenEndpointAuthMethod(final ClientAuthenticationMethod authMethod) {

		this.authMethod = authMethod;
	}
	
	
	/**
	 * Gets the URI for this client's JSON Web Key (JWK) set containing 
	 * key(s) that are used in signing requests to the server and key(s) 
	 * for encrypting responses. Corresponds to the {@code jwks_uri} client 
	 * metadata field.
	 *
	 * @return The JWK set URI, {@code null} if not specified.
	 */
	public URL getJWKSetURI() {

		return jwkSetURI;
	}


	/**
	 * Sets the URI for this client's JSON Web Key (JWK) set containing 
	 * key(s) that are used in signing requests to the server and key(s) 
	 * for encrypting responses. Corresponds to the {@code jwks_uri} client 
	 * metadata field.
	 *
	 * @param jwkSetURI The JWK set URI, {@code null} if not specified.
	 */
	public void setJWKSetURL(final URL jwkSetURI) {

		this.jwkSetURI = jwkSetURI;
	}


	/**
	 * Gets the identifier for the OAuth 2.0 client software. Corresponds
	 * to the {@code software_id} client metadata field.
	 *
	 * @return The software identifier, {@code null} if not specified.
	 */
	public SoftwareID getSoftwareID() {

		return softwareID;
	}


	/**
	 * Sets the identifier for the OAuth 2.0 client software. Corresponds
	 * to the {@code software_id} client metadata field.
	 *
	 * @param softwareID The software identifier, {@code null} if not
	 *                   specified.
	 */
	public void setSoftwareID(final SoftwareID softwareID) {

		this.softwareID = softwareID;
	}


	/**
	 * Gets the version identifier for the OAuth 2.0 client software.
	 * Corresponds to the {@code software_version} client metadata field.
	 *
	 * @return The version identifier, {@code null} if not specified.
	 */
	public SoftwareVersion getSoftwareVersion() {

		return softwareVersion;
	}


	/**
	 * Sets the version identifier for the OAuth 2.0 client software.
	 * Corresponds to the {@code software_version} client metadata field.
	 *
	 * @param softwareVersion The version identifier, {@code null} if not
	 *                        specified.
	 */
	public void setSoftwareVersion(final SoftwareVersion softwareVersion) {

		this.softwareVersion = softwareVersion;
	}
	
	
	/**
	 * Applies the client metadata defaults where no values have been
	 * specified.
	 * 
	 * <ul>
	 *     <li>The response types default to {@code ["code"]}.
	 *     <li>The grant types default to {@code "authorization_code".}
	 *     <li>The client authentication method defaults to 
	 *         "client_secret_basic".
	 * </ul>
	 */
	public void applyDefaults() {
		
		if (responseTypes == null) {
			responseTypes = new HashSet<ResponseType>();
			responseTypes.add(ResponseType.getDefault());
		}
		
		if (grantTypes == null) {
			grantTypes = new HashSet<GrantType>();
			grantTypes.add(GrantType.AUTHORIZATION_CODE);
		}
		
		if (authMethod == null) {
			authMethod = ClientAuthenticationMethod.getDefault();
		}
	}
	
	
	/**
	 * Returns the JSON object representation of this client metadata.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();

		if (redirectURIs != null) {

			JSONArray uriList = new JSONArray();

			for (URL uri: redirectURIs)
				uriList.add(uri.toString());

			o.put("redirect_uris", uriList);
		}
		
		
		if (scope != null)
			o.put("scope", scope.toString());
		
		
		if (responseTypes != null) {
			
			JSONArray rtList = new JSONArray();
			
			for (ResponseType rt: responseTypes)
				rtList.add(rt.toString());
			
			o.put("response_types", rtList);
		}
		
		
		if (grantTypes != null) {
			
			JSONArray grantList = new JSONArray();
			
			for (GrantType grant: grantTypes)
				grantList.add(grant.toString());
			
			o.put("grant_types", grantList);
		}


		if (contacts != null) {

			JSONArray contactList = new JSONArray();

			for (InternetAddress email: contacts)
				contactList.add(email.toString());

			o.put("contacts", contactList);
		}


		if (! nameEntries.isEmpty()) {

			for (Map.Entry<LangTag,String> entry: nameEntries.entrySet()) {

				LangTag langTag = entry.getKey();
				String name = entry.getValue();
				
				if (name == null)
					continue;

				if (langTag == null)
					o.put("client_name", entry.getValue());
				else
					o.put("client_name#" + langTag, entry.getValue());
			} 
		}
		
		
		if (! logoURIEntries.isEmpty()) {

			for (Map.Entry<LangTag,URL> entry: logoURIEntries.entrySet()) {

				LangTag langTag = entry.getKey();
				URL uri = entry.getValue();
				
				if (uri == null)
					continue;

				if (langTag == null)
					o.put("logo_uri", entry.getValue().toString());
				else
					o.put("logo_uri#" + langTag, entry.getValue().toString());
			} 
		}
		
		
		if (! uriEntries.isEmpty()) {

			for (Map.Entry<LangTag,URL> entry: uriEntries.entrySet()) {

				LangTag langTag = entry.getKey();
				URL uri = entry.getValue();
				
				if (uri == null)
					continue;

				if (langTag == null)
					o.put("client_uri", entry.getValue().toString());
				else
					o.put("client_uri#" + langTag, entry.getValue().toString());
			} 
		}
		
		
		if (! policyURIEntries.isEmpty()) {

			for (Map.Entry<LangTag,URL> entry: policyURIEntries.entrySet()) {

				LangTag langTag = entry.getKey();
				URL uri = entry.getValue();
				
				if (uri == null)
					continue;

				if (langTag == null)
					o.put("policy_uri", entry.getValue().toString());
				else
					o.put("policy_uri#" + langTag, entry.getValue().toString());
			} 
		}
		
		
		if (! tosURIEntries.isEmpty()) {

			for (Map.Entry<LangTag,URL> entry: tosURIEntries.entrySet()) {

				LangTag langTag = entry.getKey();
				URL uri = entry.getValue();
				
				if (uri == null)
					continue;

				if (langTag == null)
					o.put("tos_uri", entry.getValue().toString());
				else
					o.put("tos_uri#" + langTag, entry.getValue().toString());
			} 
		}


		if (authMethod != null)
			o.put("token_endpoint_auth_method", authMethod.toString());


		if (jwkSetURI != null)
			o.put("jwks_uri", jwkSetURI.toString());


		if (softwareID != null)
			o.put("software_id", softwareID.value());

		if (softwareVersion != null)
			o.put("software_version", softwareVersion.value());

		return o;
	}
	
	
	/**
	 * Parses an client metadata instance from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be  
	 *                   {@code null}.
	 *
	 * @return The client metadata.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        client metadata instance.
	 */
	public static ClientMetadata parse(final JSONObject jsonObject)
		throws ParseException {

		ClientMetadata metadata = new ClientMetadata();

		if (jsonObject.containsKey("redirect_uris")) {

			Set<URL> redirectURIs = new LinkedHashSet<URL>();

			for (String uriString: JSONObjectUtils.getStringArray(jsonObject, "redirect_uris")) {

				try {
					redirectURIs.add(new URL(uriString));

				} catch (MalformedURLException e) {

					throw new ParseException("Invalid \"redirect_uris\" parameter: " +
						                  e.getMessage());
				}
			}

			metadata.setRedirectURIs(redirectURIs);
		}
		
		
		if (jsonObject.containsKey("scope"))
			metadata.setScope(Scope.parse(JSONObjectUtils.getString(jsonObject, "scope")));
		
		
		if (jsonObject.containsKey("response_types")) {
			
			Set<ResponseType> responseTypes = new LinkedHashSet<ResponseType>();
			
			for (String rt: JSONObjectUtils.getStringArray(jsonObject, "response_types")) {
				
				responseTypes.add(ResponseType.parse(rt));
			}
			
			metadata.setResponseTypes(responseTypes);
		}
		
		
		if (jsonObject.containsKey("grant_types")) {
			
			Set<GrantType> grantTypes = new LinkedHashSet<GrantType>();
			
			for (String grant: JSONObjectUtils.getStringArray(jsonObject, "grant_types")) {
				
				grantTypes.add(new GrantType(grant));
			}
			
			metadata.setGrantTypes(grantTypes);
		}	
		

		if (jsonObject.containsKey("contacts")) {

			List<InternetAddress> emailList = new LinkedList<InternetAddress>();

			for (String emailString: JSONObjectUtils.getStringArray(jsonObject, "contacts")) {

				try {
					emailList.add(new InternetAddress(emailString));

				} catch (AddressException e) {

					throw new ParseException("Invalid \"contacts\" parameter: " +
							         e.getMessage());
				}
			}

			metadata.setContacts(emailList);
		}

		// Find lang-tagged client_name params
		Map<LangTag,Object> matches = LangTagUtils.find("client_name", jsonObject);

		for (Map.Entry<LangTag,Object> entry: matches.entrySet()) {

			try {
				metadata.setName((String)entry.getValue(), entry.getKey());

			} catch (ClassCastException e) {

				throw new ParseException("Invalid \"client_name\" (language tag) parameter");
			}
		}


		matches = LangTagUtils.find("logo_uri", jsonObject);

		for (Map.Entry<LangTag,Object> entry: matches.entrySet()) {

			try {
				metadata.setLogoURI(new URL((String)entry.getValue()), entry.getKey());

			} catch (Exception e) {

				throw new ParseException("Invalid \"logo_uri\" (language tag) parameter");
			}
		}
		
		
		matches = LangTagUtils.find("client_uri", jsonObject);

		for (Map.Entry<LangTag,Object> entry: matches.entrySet()) {

			try {
				metadata.setURI(new URL((String)entry.getValue()), entry.getKey());

			} catch (Exception e) {

				throw new ParseException("Invalid \"client_uri\" (language tag) parameter");
			}
		}
		
		
		matches = LangTagUtils.find("policy_uri", jsonObject);

		for (Map.Entry<LangTag,Object> entry: matches.entrySet()) {

			try {
				metadata.setPolicyURI(new URL((String)entry.getValue()), entry.getKey());

			} catch (Exception e) {

				throw new ParseException("Invalid \"policy_uri\" (language tag) parameter");
			}
		}
		
		
		matches = LangTagUtils.find("tos_uri", jsonObject);

		for (Map.Entry<LangTag,Object> entry: matches.entrySet()) {

			try {
				metadata.setTermsOfServiceURI(new URL((String)entry.getValue()), entry.getKey());

			} catch (Exception e) {

				throw new ParseException("Invalid \"tos_uri\" (language tag) parameter");
			}
		}
		

		if (jsonObject.containsKey("token_endpoint_auth_method"))
			metadata.setTokenEndpointAuthMethod(new ClientAuthenticationMethod(
				JSONObjectUtils.getString(jsonObject, "token_endpoint_auth_method")));

			
		if (jsonObject.containsKey("jwks_uri"))
			metadata.setJWKSetURL(JSONObjectUtils.getURL(jsonObject, "jwks_uri"));

		if (jsonObject.containsKey("software_id"))
			metadata.setSoftwareID(new SoftwareID(JSONObjectUtils.getString(jsonObject, "software_id")));

		if (jsonObject.containsKey("software_version"))
			metadata.setSoftwareVersion(new SoftwareVersion(JSONObjectUtils.getString(jsonObject, "software_version")));

		return metadata;
	}
}
