package com.nimbusds.oauth2.sdk.client;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
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
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;


/**
 * Client metadata.
 * 
 * <p>Example client metadata, serialised to a JSON object:
 * 
 * <pre>
 * {
 *  "redirect_uris"              : ["https://client.example.org/callback",
 *                                  "https://client.example.org/callback2"],
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
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591), section
 *         2.
 * </ul>
 */
public class ClientMetadata {


	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;


	/**
	 * Initialises the registered parameter name set.
	 */
	static {
		Set<String> p = new HashSet<>();

		p.add("redirect_uris");
		p.add("scope");
		p.add("response_types");
		p.add("grant_types");
		p.add("contacts");
		p.add("client_name");
		p.add("logo_uri");
		p.add("client_uri");
		p.add("policy_uri");
		p.add("tos_uri");
		p.add("token_endpoint_auth_method");
		p.add("token_endpoint_auth_signing_alg");
		p.add("jwks_uri");
		p.add("jwks");
		p.add("software_id");
		p.add("software_version");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}
	
	
	/**
	 * Redirect URIs.
	 */
	private Set<URI> redirectURIs;


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
	private final Map<LangTag,String> nameEntries;


	/**
	 * The client application logo.
	 */
	private final Map<LangTag,URI> logoURIEntries;


	/**
	 * The client URI entries.
	 */
	private final Map<LangTag,URI> uriEntries;


	/**
	 * The client policy for use of end-user data.
	 */
	private Map<LangTag,URI> policyURIEntries;


	/**
	 * The client terms of service.
	 */
	private final Map<LangTag,URI> tosURIEntries;


	/**
	 * Token endpoint authentication method.
	 */
	private ClientAuthenticationMethod authMethod;


	/**
	 * The JSON Web Signature (JWS) algorithm required for
	 * {@code private_key_jwt} and {@code client_secret_jwt}
	 * authentication at the Token endpoint.
	 */
	private JWSAlgorithm authJWSAlg;


	/**
	 * URI for this client's JSON Web Key (JWK) set containing key(s) that
	 * are used in signing requests to the server and key(s) for encrypting
	 * responses.
	 */
	private URI jwkSetURI;


	/**
	 * Client's JSON Web Key (JWK) set containing key(s) that are used in
	 * signing requests to the server and key(s) for encrypting responses.
	 * Intended as an alternative to {@link #jwkSetURI} for native clients.
	 */
	private JWKSet jwkSet;


	/**
	 * Identifier for the OAuth 2.0 client software.
	 */
	private SoftwareID softwareID;


	/**
	 * Version identifier for the OAuth 2.0 client software.
	 */
	private SoftwareVersion softwareVersion;


	/**
	 * The custom metadata fields.
	 */
	private JSONObject customFields;


	/**
	 * Creates a new OAuth 2.0 client metadata instance.
	 */
	public ClientMetadata() {

		nameEntries = new HashMap<>();
		logoURIEntries = new HashMap<>();
		uriEntries = new HashMap<>();
		policyURIEntries = new HashMap<>();
		policyURIEntries = new HashMap<>();
		tosURIEntries = new HashMap<>();
		customFields = new JSONObject();
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
		authJWSAlg = metadata.authJWSAlg;
		jwkSetURI = metadata.jwkSetURI;
		jwkSet = metadata.getJWKSet();
		softwareID = metadata.softwareID;
		softwareVersion = metadata.softwareVersion;
		customFields = metadata.customFields;
	}


	/**
	 * Gets the registered (standard) OAuth 2.0 client metadata parameter
	 * names.
	 *
	 * @return The registered parameter names, as an unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {

		return REGISTERED_PARAMETER_NAMES;
	}


	/**
	 * Gets the redirection URIs for this client. Corresponds to the
	 * {@code redirect_uris} client metadata field.
	 *
	 * @return The redirection URIs, {@code null} if not specified.
	 */
	public Set<URI> getRedirectionURIs() {

		return redirectURIs;
	}


	/**
	 * Gets the redirection URIs for this client as strings. Corresponds to
	 * the {@code redirect_uris} client metadata field.
	 *
	 * <p>This short-hand method is intended to enable string-based URI
	 * comparison.
	 *
	 * @return The redirection URIs as strings, {@code null} if not
	 *         specified.
	 */
	public Set<String> getRedirectionURIStrings() {

		if (redirectURIs == null)
			return null;

		Set<String> uriStrings = new HashSet<>();

		for (URI uri: redirectURIs)
			uriStrings.add(uri.toString());

		return uriStrings;
	}


	/**
	 * Sets the redirection URIs for this client. Corresponds to the
	 * {@code redirect_uris} client metadata field.
	 *
	 * @param redirectURIs The redirection URIs, {@code null} if not
	 *                     specified.
	 */
	public void setRedirectionURIs(final Set<URI> redirectURIs) {

		this.redirectURIs = redirectURIs;
	}


	/**
	 * Sets a single redirection URI for this client. Corresponds to the
	 * {@code redirect_uris} client metadata field.
	 *
	 * @param redirectURI The redirection URIs, {@code null} if not
	 *                    specified.
	 */
	public void setRedirectionURI(final URI redirectURI) {

		if (redirectURI != null) {
			redirectURIs = new HashSet<>(Collections.singletonList(redirectURI));
		} else {
			redirectURIs = null;
		}
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
	 * Checks if the scope matadata field is set and contains the specified
	 * scope value.
	 *
	 * @param scopeValue The scope value. Must not be {@code null}.
	 *
	 * @return {@code true} if the scope value is contained, else
	 *         {@code false}.
	 */
	public boolean hasScopeValue(final Scope.Value scopeValue) {

		return scope != null && scope.contains(scopeValue);
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
	public URI getLogoURI() {

		return getLogoURI(null);
	}


	/**
	 * Gets the client application logo. Corresponds to the
	 * {@code logo_uri} client metadata field, with an optional
	 * language tag.
	 *
	 * @return The logo URI, {@code null} if not specified.
	 */
	public URI getLogoURI(final LangTag langTag) {

		return logoURIEntries.get(langTag);
	}


	/**
	 * Gets the client application logo entries. Corresponds to the
	 * {@code logo_uri} client metadata field.
	 *
	 * @return The logo URI entries, empty map if none.
	 */
	public Map<LangTag,URI> getLogoURIEntries() {

		return logoURIEntries;
	}


	/**
	 * Sets the client application logo. Corresponds to the
	 * {@code logo_uri} client metadata field, with no language
	 * tag.
	 *
	 * @param logoURI The logo URI, {@code null} if not specified.
	 */
	public void setLogoURI(final URI logoURI) {

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
	public void setLogoURI(final URI logoURI, final LangTag langTag) {

		logoURIEntries.put(langTag, logoURI);
	}


	/**
	 * Gets the client home page. Corresponds to the {@code client_uri}
	 * client metadata field, with no language tag.
	 *
	 * @return The client URI, {@code null} if not specified.
	 */
	public URI getURI() {

		return getURI(null);
	}


	/**
	 * Gets the client home page. Corresponds to the {@code client_uri}
	 * client metadata field, with an optional language tag.
	 *
	 * @return The client URI, {@code null} if not specified.
	 */
	public URI getURI(final LangTag langTag) {

		return uriEntries.get(langTag);
	}


	/**
	 * Gets the client home page entries. Corresponds to the
	 * {@code client_uri} client metadata field.
	 *
	 * @return The client URI entries, empty map if none.
	 */
	public Map<LangTag,URI> getURIEntries() {

		return uriEntries;
	}


	/**
	 * Sets the client home page. Corresponds to the {@code client_uri}
	 * client metadata field, with no language tag.
	 *
	 * @param uri The client URI, {@code null} if not specified.
	 */
	public void setURI(final URI uri) {

		uriEntries.put(null, uri);
	}


	/**
	 * Sets the client home page. Corresponds to the {@code client_uri}
	 * client metadata field, with an optional language tag.
	 *
	 * @param uri     The URI. Must not be {@code null}.
	 * @param langTag The language tag, {@code null} if not specified.
	 */
	public void setURI(final URI uri, final LangTag langTag) {

		uriEntries.put(langTag, uri);
	}


	/**
	 * Gets the client policy for use of end-user data. Corresponds to the
	 * {@code policy_uri} client metadata field, with no language
	 * tag.
	 *
	 * @return The policy URI, {@code null} if not specified.
	 */
	public URI getPolicyURI() {

		return getPolicyURI(null);
	}


	/**
	 * Gets the client policy for use of end-user data. Corresponds to the
	 * {@code policy_uri} client metadata field, with an optional
	 * language tag.
	 *
	 * @return The policy URI, {@code null} if not specified.
	 */
	public URI getPolicyURI(final LangTag langTag) {

		return policyURIEntries.get(langTag);
	}


	/**
	 * Gets the client policy entries for use of end-user data.
	 * Corresponds to the {@code policy_uri} client metadata field.
	 *
	 * @return The policy URI entries, empty map if none.
	 */
	public Map<LangTag,URI> getPolicyURIEntries() {

		return policyURIEntries;
	}


	/**
	 * Sets the client policy for use of end-user data. Corresponds to the
	 * {@code policy_uri} client metadata field, with no language
	 * tag.
	 *
	 * @param policyURI The policy URI, {@code null} if not specified.
	 */
	public void setPolicyURI(final URI policyURI) {

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
	public void setPolicyURI(final URI policyURI, final LangTag langTag) {

		policyURIEntries.put(langTag, policyURI);
	}


	/**
	 * Gets the client's terms of service. Corresponds to the
	 * {@code tos_uri} client metadata field, with no language
	 * tag.
	 *
	 * @return The terms of service URI, {@code null} if not specified.
	 */
	public URI getTermsOfServiceURI() {

		return getTermsOfServiceURI(null);
	}


	/**
	 * Gets the client's terms of service. Corresponds to the
	 * {@code tos_uri} client metadata field, with an optional
	 * language tag.
	 *
	 * @return The terms of service URI, {@code null} if not specified.
	 */
	public URI getTermsOfServiceURI(final LangTag langTag) {

		return tosURIEntries.get(langTag);
	}


	/**
	 * Gets the client's terms of service entries. Corresponds to the
	 * {@code tos_uri} client metadata field.
	 *
	 * @return The terms of service URI entries, empty map if none.
	 */
	public Map<LangTag,URI> getTermsOfServiceURIEntries() {

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
	public void setTermsOfServiceURI(final URI tosURI) {

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
	public void setTermsOfServiceURI(final URI tosURI, final LangTag langTag) {

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
	 * Gets the JSON Web Signature (JWS) algorithm required for
	 * {@code private_key_jwt} and {@code client_secret_jwt}
	 * authentication at the Token endpoint. Corresponds to the
	 * {@code token_endpoint_auth_signing_alg} client metadata field.
	 *
	 * @return The JWS algorithm, {@code null} if not specified.
	 */
	public JWSAlgorithm getTokenEndpointAuthJWSAlg() {

		return authJWSAlg;
	}


	/**
	 * Sets the JSON Web Signature (JWS) algorithm required for
	 * {@code private_key_jwt} and {@code client_secret_jwt}
	 * authentication at the Token endpoint. Corresponds to the
	 * {@code token_endpoint_auth_signing_alg} client metadata field.
	 *
	 * @param authJWSAlg The JWS algorithm, {@code null} if not specified.
	 */
	public void setTokenEndpointAuthJWSAlg(final JWSAlgorithm authJWSAlg) {

		this.authJWSAlg = authJWSAlg;
	}


	/**
	 * Gets the URI for this client's JSON Web Key (JWK) set containing
	 * key(s) that are used in signing requests to the server and key(s)
	 * for encrypting responses. Corresponds to the {@code jwks_uri} client
	 * metadata field.
	 *
	 * @return The JWK set URI, {@code null} if not specified.
	 */
	public URI getJWKSetURI() {

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
	public void setJWKSetURI(final URI jwkSetURI) {

		this.jwkSetURI = jwkSetURI;
	}


	/**
	 * Gets this client's JSON Web Key (JWK) set containing key(s) that are
	 * used in signing requests to the server and key(s) for encrypting
	 * responses. Intended as an alternative to {@link #getJWKSetURI} for
	 * native clients. Corresponds to the {@code jwks} client metadata
	 * field.
	 *
	 * @return The JWK set, {@code null} if not specified.
	 */
	public JWKSet getJWKSet() {

		return jwkSet;
	}


	/**
	 * Sets this client's JSON Web Key (JWK) set containing key(s) that are
	 * used in signing requests to the server and key(s) for encrypting
	 * responses. Intended as an alternative to {@link #getJWKSetURI} for
	 * native clients. Corresponds to the {@code jwks} client metadata
	 * field.
	 *
	 * @param jwkSet The JWK set, {@code null} if not specified.
	 */
	public void setJWKSet(final JWKSet jwkSet) {

		this.jwkSet = jwkSet;
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
	 * Gets the specified custom metadata field.
	 *
	 * @param name The field name. Must not be {@code null}.
	 *
	 * @return The field value, typically serialisable to a JSON entity,
	 *         {@code null} if none.
	 */
	public Object getCustomField(final String name) {

		return customFields.get(name);
	}


	/**
	 * Gets the custom metadata fields.
	 *
	 * @return The custom metadata fields, as a JSON object, empty object
	 *         if none.
	 */
	public JSONObject getCustomFields() {

		return customFields;
	}


	/**
	 * Sets the specified custom metadata field.
	 *
	 * @param name  The field name. Must not be {@code null}.
	 * @param value The field value. Should serialise to a JSON entity.
	 */
	public void setCustomField(final String name, final Object value) {

		customFields.put(name, value);
	}


	/**
	 * Sets the custom metadata fields.
	 *
	 * @param customFields The custom metadata fields, as a JSON object,
	 *                     empty object if none. Must not be {@code null}.
	 */
	public void setCustomFields(final JSONObject customFields) {

		if (customFields == null)
			throw new IllegalArgumentException("The custom fields JSON object must not be null");

		this.customFields = customFields;
	}


	/**
	 * Applies the client metadata defaults where no values have been
	 * specified.
	 *
	 * <ul>
	 *     <li>The response types default to {@code ["code"]}.
	 *     <li>The grant types default to {@code ["authorization_code"]}.
	 *     <li>The client authentication method defaults to
	 *         "client_secret_basic", unless the grant type is "implicit"
	 *         only.
	 * </ul>
	 */
	public void applyDefaults() {

		if (responseTypes == null) {
			responseTypes = new HashSet<>();
			responseTypes.add(ResponseType.getDefault());
		}

		if (grantTypes == null) {
			grantTypes = new HashSet<>();
			grantTypes.add(GrantType.AUTHORIZATION_CODE);
		}

		if (authMethod == null) {

			if (grantTypes.contains(GrantType.IMPLICIT) && grantTypes.size() == 1) {
				authMethod = ClientAuthenticationMethod.NONE;
			} else {
				authMethod = ClientAuthenticationMethod.getDefault();
			}
		}
	}


	/**
	 * Returns the JSON object representation of this client metadata,
	 * including any custom fields.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {

		return toJSONObject(true);
	}


	/**
	 * Returns the JSON object representation of this client metadata.
	 *
	 * @param includeCustomFields {@code true} to include any custom
	 *                            metadata fields, {@code false} to omit
	 *                            them.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject(final boolean includeCustomFields) {

		JSONObject o;

		if (includeCustomFields)
			o = new JSONObject(customFields);
		else
			o = new JSONObject();


		if (redirectURIs != null) {

			JSONArray uriList = new JSONArray();

			for (URI uri: redirectURIs)
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

			for (Map.Entry<LangTag,URI> entry: logoURIEntries.entrySet()) {

				LangTag langTag = entry.getKey();
				URI uri = entry.getValue();

				if (uri == null)
					continue;

				if (langTag == null)
					o.put("logo_uri", entry.getValue().toString());
				else
					o.put("logo_uri#" + langTag, entry.getValue().toString());
			}
		}


		if (! uriEntries.isEmpty()) {

			for (Map.Entry<LangTag,URI> entry: uriEntries.entrySet()) {

				LangTag langTag = entry.getKey();
				URI uri = entry.getValue();

				if (uri == null)
					continue;

				if (langTag == null)
					o.put("client_uri", entry.getValue().toString());
				else
					o.put("client_uri#" + langTag, entry.getValue().toString());
			}
		}


		if (! policyURIEntries.isEmpty()) {

			for (Map.Entry<LangTag,URI> entry: policyURIEntries.entrySet()) {

				LangTag langTag = entry.getKey();
				URI uri = entry.getValue();

				if (uri == null)
					continue;

				if (langTag == null)
					o.put("policy_uri", entry.getValue().toString());
				else
					o.put("policy_uri#" + langTag, entry.getValue().toString());
			}
		}


		if (! tosURIEntries.isEmpty()) {

			for (Map.Entry<LangTag,URI> entry: tosURIEntries.entrySet()) {

				LangTag langTag = entry.getKey();
				URI uri = entry.getValue();

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


		if (authJWSAlg != null)
			o.put("token_endpoint_auth_signing_alg", authJWSAlg.getName());


		if (jwkSetURI != null)
			o.put("jwks_uri", jwkSetURI.toString());


		if (jwkSet != null)
			o.put("jwks", jwkSet.toJSONObject(true)); // prevent private keys from leaking


		if (softwareID != null)
			o.put("software_id", softwareID.getValue());

		if (softwareVersion != null)
			o.put("software_version", softwareVersion.getValue());

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

		// Copy JSON object, then parse
		return parseFromModifiableJSONObject(new JSONObject(jsonObject));
	}


	/**
	 * Parses an client metadata instance from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse, will be modified by
	 *                   the parse routine. Must not be {@code null}.
	 *
	 * @return The client metadata.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        client metadata instance.
	 */
	private static ClientMetadata parseFromModifiableJSONObject(final JSONObject jsonObject)
		throws ParseException {

		ClientMetadata metadata = new ClientMetadata();

		if (jsonObject.containsKey("redirect_uris")) {

			Set<URI> redirectURIs = new LinkedHashSet<>();

			for (String uriString: JSONObjectUtils.getStringArray(jsonObject, "redirect_uris")) {

				try {
					redirectURIs.add(new URI(uriString));

				} catch (URISyntaxException e) {

					throw new ParseException("Invalid \"redirect_uris\" parameter: " +
						                  e.getMessage());
				}
			}

			metadata.setRedirectionURIs(redirectURIs);
			jsonObject.remove("redirect_uris");
		}


		if (jsonObject.containsKey("scope")) {
			metadata.setScope(Scope.parse(JSONObjectUtils.getString(jsonObject, "scope")));
			jsonObject.remove("scope");
		}


		if (jsonObject.containsKey("response_types")) {

			Set<ResponseType> responseTypes = new LinkedHashSet<>();

			for (String rt: JSONObjectUtils.getStringArray(jsonObject, "response_types")) {

				responseTypes.add(ResponseType.parse(rt));
			}

			metadata.setResponseTypes(responseTypes);
			jsonObject.remove("response_types");
		}


		if (jsonObject.containsKey("grant_types")) {

			Set<GrantType> grantTypes = new LinkedHashSet<>();

			for (String grant: JSONObjectUtils.getStringArray(jsonObject, "grant_types")) {

				grantTypes.add(GrantType.parse(grant));
			}

			metadata.setGrantTypes(grantTypes);
			jsonObject.remove("grant_types");
		}


		if (jsonObject.containsKey("contacts")) {

			List<InternetAddress> emailList = new LinkedList<>();

			for (String emailString: JSONObjectUtils.getStringArray(jsonObject, "contacts")) {

				try {
					emailList.add(new InternetAddress(emailString));

				} catch (AddressException e) {

					throw new ParseException("Invalid \"contacts\" parameter: " +
							         e.getMessage());
				}
			}

			metadata.setContacts(emailList);
			jsonObject.remove("contacts");
		}


		// Find lang-tagged client_name params
		Map<LangTag,Object> matches = LangTagUtils.find("client_name", jsonObject);

		for (Map.Entry<LangTag,Object> entry: matches.entrySet()) {

			try {
				metadata.setName((String)entry.getValue(), entry.getKey());

			} catch (ClassCastException e) {

				throw new ParseException("Invalid \"client_name\" (language tag) parameter");
			}

			removeMember(jsonObject, "client_name", entry.getKey());
		}


		matches = LangTagUtils.find("logo_uri", jsonObject);

		for (Map.Entry<LangTag,Object> entry: matches.entrySet()) {

			try {
				metadata.setLogoURI(new URI((String)entry.getValue()), entry.getKey());

			} catch (Exception e) {

				throw new ParseException("Invalid \"logo_uri\" (language tag) parameter");
			}

			removeMember(jsonObject, "logo_uri", entry.getKey());
		}


		matches = LangTagUtils.find("client_uri", jsonObject);

		for (Map.Entry<LangTag,Object> entry: matches.entrySet()) {

			try {
				metadata.setURI(new URI((String)entry.getValue()), entry.getKey());


			} catch (Exception e) {

				throw new ParseException("Invalid \"client_uri\" (language tag) parameter");
			}

			removeMember(jsonObject, "client_uri", entry.getKey());
		}


		matches = LangTagUtils.find("policy_uri", jsonObject);

		for (Map.Entry<LangTag,Object> entry: matches.entrySet()) {

			try {
				metadata.setPolicyURI(new URI((String)entry.getValue()), entry.getKey());

			} catch (Exception e) {

				throw new ParseException("Invalid \"policy_uri\" (language tag) parameter");
			}

			removeMember(jsonObject, "policy_uri", entry.getKey());
		}


		matches = LangTagUtils.find("tos_uri", jsonObject);

		for (Map.Entry<LangTag,Object> entry: matches.entrySet()) {

			try {
				metadata.setTermsOfServiceURI(new URI((String)entry.getValue()), entry.getKey());

			} catch (Exception e) {

				throw new ParseException("Invalid \"tos_uri\" (language tag) parameter");
			}

			removeMember(jsonObject, "tos_uri", entry.getKey());
		}


		if (jsonObject.containsKey("token_endpoint_auth_method")) {
			metadata.setTokenEndpointAuthMethod(new ClientAuthenticationMethod(
				JSONObjectUtils.getString(jsonObject, "token_endpoint_auth_method")));

			jsonObject.remove("token_endpoint_auth_method");
		}


		if (jsonObject.containsKey("token_endpoint_auth_signing_alg")) {
			metadata.setTokenEndpointAuthJWSAlg(new JWSAlgorithm(
				JSONObjectUtils.getString(jsonObject, "token_endpoint_auth_signing_alg")));

			jsonObject.remove("token_endpoint_auth_signing_alg");
		}


		if (jsonObject.containsKey("jwks_uri")) {
			metadata.setJWKSetURI(JSONObjectUtils.getURI(jsonObject, "jwks_uri"));
			jsonObject.remove("jwks_uri");
		}

		if (jsonObject.containsKey("jwks")) {

			try {
				metadata.setJWKSet(JWKSet.parse(JSONObjectUtils.getJSONObject(jsonObject, "jwks")));

			} catch (java.text.ParseException e) {
				throw new ParseException(e.getMessage(), e);
			}

			jsonObject.remove("jwks");
		}

		if (jsonObject.containsKey("software_id")) {
			metadata.setSoftwareID(new SoftwareID(JSONObjectUtils.getString(jsonObject, "software_id")));
			jsonObject.remove("software_id");
		}

		if (jsonObject.containsKey("software_version")) {
			metadata.setSoftwareVersion(new SoftwareVersion(JSONObjectUtils.getString(jsonObject, "software_version")));
			jsonObject.remove("software_version");
		}

		// The remaining fields are custom
		metadata.customFields = jsonObject;

		return metadata;
	}


	/**
	 * Removes a JSON object member with the specified base name and
	 * optional language tag.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 * @param name       The base member name. Must not be {@code null}.
	 * @param langTag    The language tag, {@code null} if none.
	 */
	private static void removeMember(final JSONObject jsonObject, final String name, final LangTag langTag) {

		if (langTag == null)
			jsonObject.remove(name);
		else
			jsonObject.remove(name + "#" + langTag);
	}
}
