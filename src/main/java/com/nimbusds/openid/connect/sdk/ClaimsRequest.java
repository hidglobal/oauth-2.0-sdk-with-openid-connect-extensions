package com.nimbusds.openid.connect.sdk;


import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.jcip.annotations.Immutable;

import org.apache.commons.lang3.tuple.ImmutablePair;

import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;

import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;


/**
 * Specifies the individual claims to return from the UserInfo endpoint and / 
 * or in the ID Token.
 *
 * <p>Related specifications: 
 * 
 * <ul>
 *     <li>OpenID Connect Messages, section 2.6.
 * </ul>
 */
public class ClaimsRequest {


	/**
	 * Individual claim request. This class is immutable.
	 *
	 * <p>Related specifications: 
	 * 
	 * <ul>
	 *     <li>OpenID Connect Messages, section 2.6.1.
	 * </ul>
	 */
	@Immutable
	public static class Entry {


		/**
		 * The claim name.
		 */
		private final String claimName;


		/**
		 * The claim requirement.
		 */
		private final ClaimRequirement requirement;


		/**
		 * Optional language tag.
		 */
		private final LangTag langTag;


		/**
		 * Optional claim value.
		 */
		private final String value;


		/**
		 * Optional claim values.
		 */
		private final List<String> values;


		/**
		 * Creates a new individual claim request. The claim 
		 * requirement is set to voluntary (the default) and no 
		 * expected value(s) are specified.
		 *
		 * @param claimName   The claim name. Must not be {@code null}.
		 * @param langTag     Optional language tag for the claim.
		 */
		public Entry(final String claimName, final LangTag langTag) {

			this(claimName, ClaimRequirement.VOLUNTARY, langTag, null, null);
		}
		
		
		/**
		 * Creates a new individual claim request.
		 *
		 * @param claimName   The claim name. Must not be {@code null}.
		 * @param requirement The claim requirement. Must not be 
		 *                    {@code null}.
		 */
		public Entry(final String claimName, final ClaimRequirement requirement) {

			this(claimName, requirement, null, null, null);
		}


		/**
		 * Creates a new individual claim request.
		 *
		 * @param claimName   The claim name. Must not be {@code null}.
		 * @param requirement The claim requirement. Must not be 
		 *                    {@code null}.
		 * @param langTag     Optional language tag for the claim.
		 * @param value       Optional expected value for the claim.
		 */
		public Entry(final String claimName, final ClaimRequirement requirement, 
			     final LangTag langTag, final String value) {

			this(claimName, requirement, langTag, value, null);
		}


		/**
		 * Creates a new individual claim request.
		 *
		 * @param claimName   The claim name. Must not be {@code null}.
		 * @param requirement The claim requirement. Must not be 
		 *                    {@code null}.
		 * @param langTag     Optional language tag for the claim.
		 * @param values      Optional expected values for the claim.
		 */
		public Entry(final String claimName, final ClaimRequirement requirement, 
			     final LangTag langTag, final List<String> values) {

			this(claimName, requirement, langTag, null, values);
		}


		/**
		 * Creates a new individual claim request. This constructor is
		 * to be used privately. Ensures that {@code value} and 
		 * {@code values} are not simultaneously specified.
		 *
		 * @param claimName   The claim name. Must not be {@code null}.
		 * @param requirement The claim requirement. Must not be 
		 *                    {@code null}.
		 * @param langTag     Optional language tag for the claim.
		 * @param value       Optional expected value for the claim. If
		 *                    set, then the {@code values} parameter
		 *                    must not be set.
		 * @param values      Optional expected values for the claim. 
		 *                    If set, then the {@code value} parameter
		 *                    must not be set.
		 */
		private Entry(final String claimName, final ClaimRequirement requirement, final LangTag langTag, 
			      final String value, final List<String> values) {

			if (claimName == null)
				throw new IllegalArgumentException("The claim name must not be null");

			this.claimName = claimName;


			if (requirement == null)
				throw new IllegalArgumentException("The claim requirement must not be null");

			this.requirement = requirement;


			this.langTag = langTag;


			if (value != null && values == null) {

				this.value = value;
				this.values = null;

			} else if (value == null && values != null) {

				this.value = null;
				this.values = values;

			} else if (value == null && values == null) {

				this.value = null;
				this.values = null;

			} else {

				throw new IllegalArgumentException("Either value or values must be specified, but not both");
			}
		}


		/**
		 * Gets the claim name.
		 *
		 * @return The claim name.
		 */
		public String getClaimName() {

			return claimName;
		}
		
		
		/**
		 * Gets the claim name, optionally with the language tag
		 * appended.
		 * 
		 * <p>Example with language tag:
		 * 
		 * <pre>
		 * name#de-DE
		 * </pre>
		 * 
		 * @param withLangTag If {@code true} the language tag will be
		 *                    appended to the name (if any), else not.
		 * 
		 * @return The claim name, with optionally appended language
		 *         tag.
		 */
		public String getClaimName(final boolean withLangTag) {
			
			if (withLangTag && langTag != null)
				return claimName + "#" + langTag.toString();
			else
				return claimName;
		}


		/**
		 * Gets the claim requirement.
		 *
		 * @return The claim requirement.
		 */
		public ClaimRequirement getClaimRequirement() {

			return requirement;
		}


		/**
		 * Gets the optional language tag for the claim.
		 *
		 * @return The language tag, {@code null} if not specified.
		 */
		public LangTag getLangTag() {

			return langTag;
		}


		/**
		 * Gets the optional value for the claim.
		 *
		 * @return The value, {@code null} if not specified.
		 */
		public String getValue() {

			return value;
		}


		/**
		 * Gets the optional values for the claim.
		 *
		 * @return The values, {@code null} if not specified.
		 */
		public List<String> getValues() {

			return values;
		}


		/**
		 * Returns the JSON object representation of the specified 
		 * collection of individual claim requests.
		 *
		 * <p>Example:
		 *
		 * <pre>
		 * {
		 *   "given_name": {"essential": true},
		 *   "nickname": null,
		 *   "email": {"essential": true},
		 *   "email_verified": {"essential": true},
		 *   "picture": null,
		 *   "http://example.info/claims/groups": null
		 * }  
		 * </pre>
		 *
		 * @param entries The entries to serialise. Must not be 
		 *                {@code null}.
		 *
		 * @return The corresponding JSON object, empty if no claims 
		 *         were found.
		 */
		public static JSONObject toJSONObject(final Collection<Entry> entries) {

			JSONObject o = new JSONObject();

			for (Entry entry: entries) {

				// Compose the optional value
				JSONObject entrySpec = null;

				if (entry.getValue() != null) {

					entrySpec = new JSONObject();
					entrySpec.put("value", entry.getValue());
				}

				if (entry.getValues() != null) {

					// Either "value" or "values", or none
					// may be defined
					entrySpec = new JSONObject();
					entrySpec.put("values", entry.getValues());
				}

				if (entry.getClaimRequirement().equals(ClaimRequirement.ESSENTIAL)) {

					if (entrySpec == null)
						entrySpec = new JSONObject();

					entrySpec.put("essential", true);
				}

				o.put(entry.getClaimName(true), entrySpec);
			}

			return o;
		}


		/**
		 * Parses a collection of individual claim requests from the
		 * specified JSON object. Request entries that are not 
		 * understood are silently ignored.
		 */
		public static Collection<Entry> parseEntries(final JSONObject jsonObject) {

			Collection<Entry> entries = new LinkedList<Entry>();

			if (jsonObject.isEmpty())
				return entries;

			for (Map.Entry<String,Object> member: jsonObject.entrySet()) {

				// Process the key
				String claimNameWithOptLangTag = member.getKey();

				String claimName;
				LangTag langTag = null;

				if (claimNameWithOptLangTag.contains("#")) {

					String[] parts = claimNameWithOptLangTag.split("#", 2);

					claimName = parts[0];

					try {
						langTag = LangTag.parse(parts[1]);

					} catch (LangTagException e) {

						// Ignore and continue
						continue;
					}

				} else {
					claimName = claimNameWithOptLangTag;
				}

				// Parse the optional value
				if (member.getValue() == null) {

					// Voluntary claim with no value(s)
					entries.add(new Entry(claimName, langTag));
					continue;
				}

				try {
					JSONObject entrySpec = (JSONObject)member.getValue();

					ClaimRequirement requirement = ClaimRequirement.VOLUNTARY;

					if (entrySpec.containsKey("essential")) {

						boolean isEssential = (Boolean)entrySpec.get("essential");

						if (isEssential)
							requirement = ClaimRequirement.ESSENTIAL;
					}

					if (entrySpec.containsKey("value")) {

						String expectedValue = (String)entrySpec.get("value");

						entries.add(new Entry(claimName, requirement, langTag, expectedValue));

					} else if (entrySpec.containsKey("values")) {

						List<String> expectedValues = new LinkedList<String>();

						for (Object v: (List)entrySpec.get("values")) {

							expectedValues.add((String)v);
						}

						entries.add(new Entry(claimName, requirement, langTag, expectedValues));

					} else {
						entries.add(new Entry(claimName, requirement, langTag, (String)null));
					}

				} catch (Exception e) {
					// Ignore and continue
				}
			}

			return entries;
		}
	}


	/**
	 * The requested ID token claims, keyed by claim name and language tag.
	 */
	private final Map<ImmutablePair<String,LangTag>,Entry> idTokenClaims =
		new HashMap<ImmutablePair<String,LangTag>,Entry>();


	/**
	 * The requested UserInfo claims, keyed by claim name and language tag.
	 */
	private final Map<ImmutablePair<String,LangTag>,Entry> userInfoClaims =
		new HashMap<ImmutablePair<String,LangTag>,Entry>();	
	

	/**
	 * Creates a new empty claims request.
	 */
	public ClaimsRequest() {

		// Nothing to initialise
	}
	
	
	/**
	 * Adds the entries from the specified other claims request.
	 * 
	 * @param other The other claims request. If {@code null} no claims
	 *              request entries will be added to this claims request.
	 */
	public void add(final ClaimsRequest other) {
		
		if (other == null)
			return;
		
		idTokenClaims.putAll(other.idTokenClaims);
		userInfoClaims.putAll(other.userInfoClaims);
	}


	/**
	 * Adds the specified ID token claim to the request. It is marked as
	 * voluntary and no language tag and value(s) are associated with it.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
	 */
	public void addIDTokenClaim(final String claimName) {

		addIDTokenClaim(claimName, ClaimRequirement.VOLUNTARY);
	}


	/**
	 * Adds the specified ID token claim to the request. No language tag 
	 * and value(s) are associated with it.
	 *
	 * @param claimName   The claim name. Must not be {@code null}.
	 * @param requirement The claim requirement. Must not be {@code null}.
	 */
	public void addIDTokenClaim(final String claimName, final ClaimRequirement requirement) {

		addIDTokenClaim(claimName, requirement, null);
	}


	/**
	 * Adds the specified ID token claim to the request. No value(s) are 
	 * associated with it.
	 *
	 * @param claimName   The claim name. Must not be {@code null}.
	 * @param requirement The claim requirement. Must not be {@code null}.
	 * @param langTag     The associated language tag, {@code null} if not
	 *                    specified.
	 */
	public void addIDTokenClaim(final String claimName, final ClaimRequirement requirement, 
		                    final LangTag langTag) {


		addIDTokenClaim(claimName, requirement, langTag, (String)null);
	}


	/**
	 * Adds the specified ID token claim to the request.
	 *
	 * @param claimName   The claim name. Must not be {@code null}.
	 * @param requirement The claim requirement. Must not be {@code null}.
	 * @param langTag     The associated language tag, {@code null} if not
	 *                    specified.
	 * @param value       The expected claim value, {@code null} if not
	 *                    specified.
	 */
	public void addIDTokenClaim(final String claimName, final ClaimRequirement requirement, 
		                    final LangTag langTag, final String value) {

		addIDTokenClaim(new Entry(claimName, requirement, langTag, value));
	}


	/**
	 * Adds the specified ID token claim to the request.
	 *
	 * @param claimName   The claim name. Must not be {@code null}.
	 * @param requirement The claim requirement. Must not be {@code null}.
	 * @param langTag     The associated language tag, {@code null} if not
	 *                    specified.
	 * @param values      The expected claim values, {@code null} if not
	 *                    specified.
	 */
	public void addIDTokenClaim(final String claimName, final ClaimRequirement requirement, 
		                    final LangTag langTag, final List<String> values) {

		addIDTokenClaim(new Entry(claimName, requirement, langTag, values));
	}


	/**
	 * Adds the specified ID token claim to the request.
	 *
	 * @param entry The individual ID token claim request. Must not be
	 *              {@code null}.
	 */
	public void addIDTokenClaim(final Entry entry) {

		ImmutablePair<String,LangTag> key = 
			new ImmutablePair<String,LangTag>(entry.getClaimName(), entry.getLangTag());

		idTokenClaims.put(key, entry);
	}


	/**
	 * Gets the requested ID token claims.
	 *
	 * @return The ID token claims, as an unmodifiable collection, empty 
	 *         set if none.
	 */
	public Collection<Entry> getIDTokenClaims() {

		return Collections.unmodifiableCollection(idTokenClaims.values());
	}
	
	
	/**
	 * Gets the names of the requested ID token claim names.
	 * 
	 * @param withLangTag If {@code true} the language tags, if any, will 
	 *                    be appended to the names, else not.
	 * 
	 * 
	 * @return The ID token claim names, as an unmodifiable set, empty set
	 *         if none.
	 */
	public Set<String> getIDTokenClaimNames(final boolean withLangTag) {
		
		Set<String> names = new HashSet<String>();
		
		for (Entry en: idTokenClaims.values())
			names.add(en.getClaimName(withLangTag));
		
		return Collections.unmodifiableSet(names);
	}


	/**
	 * Removes the specified ID token claim from the request.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
	 * @param langTag   The associated language tag, {@code null} if none.
	 *
	 * @return The removed ID token claim, {@code null} if not found.
	 */
	public Entry removeIDTokenClaim(final String claimName, final LangTag langTag) {

		ImmutablePair<String,LangTag> key = 
			new ImmutablePair<String,LangTag>(claimName, langTag);

		return idTokenClaims.remove(key);
	}


	/**
	 * Removes the specified ID token claims from the request, in all
	 * existing language tag variations.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
	 *
	 * @return The removed ID token claims, as an unmodifiable collection,
	 *         empty set if none were found.
	 */
	public Collection<Entry> removeIDTokenClaims(final String claimName) {

		Collection<Entry> removedClaims = new LinkedList<Entry>();

		Iterator<Map.Entry<ImmutablePair<String,LangTag>,Entry>> it = idTokenClaims.entrySet().iterator();

		while (it.hasNext()) {

			Map.Entry<ImmutablePair<String,LangTag>,Entry> reqEntry = it.next();

			if (reqEntry.getKey().getLeft().equals(claimName)) {

				removedClaims.add(reqEntry.getValue());

				it.remove();
			}
		}

		return Collections.unmodifiableCollection(removedClaims);
	}


	/**
	 * Adds the specified UserInfo claim to the request. It is marked as
	 * voluntary and no language tag and value(s) are associated with it.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
	 */
	public void addUserInfoClaim(final String claimName) {

		addUserInfoClaim(claimName, ClaimRequirement.VOLUNTARY);
	}


	/**
	 * Adds the specified UserInfo claim to the request. No language tag 
	 * and value(s) are associated with it.
	 *
	 * @param claimName   The claim name. Must not be {@code null}.
	 * @param requirement The claim requirement. Must not be {@code null}.
	 */
	public void addUserInfoClaim(final String claimName, final ClaimRequirement requirement) {

		addUserInfoClaim(claimName, requirement, null);
	}


	/**
	 * Adds the specified UserInfo claim to the request. No value(s) are 
	 * associated with it.
	 *
	 * @param claimName   The claim name. Must not be {@code null}.
	 * @param requirement The claim requirement. Must not be {@code null}.
	 * @param langTag     The associated language tag, {@code null} if not
	 *                    specified.
	 */
	public void addUserInfoClaim(final String claimName, final ClaimRequirement requirement, 
		                     final LangTag langTag) {


		addUserInfoClaim(claimName, requirement, langTag, (String)null);
	}


	/**
	 * Adds the specified UserInfo claim to the request.
	 *
	 * @param claimName   The claim name. Must not be {@code null}.
	 * @param requirement The claim requirement. Must not be {@code null}.
	 * @param langTag     The associated language tag, {@code null} if not
	 *                    specified.
	 * @param value       The expected claim value, {@code null} if not
	 *                    specified.
	 */
	public void addUserInfoClaim(final String claimName, final ClaimRequirement requirement, 
		                     final LangTag langTag, final String value) {

		addUserInfoClaim(new Entry(claimName, requirement, langTag, value));
	}


	/**
	 * Adds the specified UserInfo claim to the request.
	 *
	 * @param claimName   The claim name. Must not be {@code null}.
	 * @param requirement The claim requirement. Must not be {@code null}.
	 * @param langTag     The associated language tag, {@code null} if not
	 *                    specified.
	 * @param values      The expected claim values, {@code null} if not
	 *                    specified.
	 */
	public void addUserInfoClaim(final String claimName, final ClaimRequirement requirement, 
		                     final LangTag langTag, final List<String> values) {

		addUserInfoClaim(new Entry(claimName, requirement, langTag, values));
	}


	/**
	 * Adds the specified UserInfo claim to the request.
	 *
	 * @param entry The individual UserInfo claim request. Must not be
	 *              {@code null}.
	 */
	public void addUserInfoClaim(final Entry entry) {

		ImmutablePair<String,LangTag> key = 
			new ImmutablePair<String,LangTag>(entry.getClaimName(), entry.getLangTag());

		userInfoClaims.put(key, entry);
	}


	/**
	 * Gets the requested UserInfo claims.
	 *
	 * @return The UserInfo claims, as an unmodifiable collection, empty 
	 *         set if none.
	 */
	public Collection<Entry> getUserInfoClaims() {

		return Collections.unmodifiableCollection(userInfoClaims.values());
	}
	
	
	/**
	 * Gets the names of the requested UserInfo claim names.
	 * 
	 * @param withLangTag If {@code true} the language tags, if any, will 
	 *                    be appended to the names, else not.
	 * 
	 * 
	 * @return The UserInfo claim names, as an unmodifiable set, empty set
	 *         if none.
	 */
	public Set<String> getUserInfoClaimNames(final boolean withLangTag) {
		
		Set<String> names = new HashSet<String>();
		
		for (Entry en: userInfoClaims.values())
			names.add(en.getClaimName(withLangTag));
		
		return Collections.unmodifiableSet(names);
	}


	/**
	 * Removes the specified UserInfo claim from the request.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
	 * @param langTag   The associated language tag, {@code null} if none.
	 *
	 * @return The removed UserInfo claim, {@code null} if not found.
	 */
	public Entry removeUserInfoClaim(final String claimName, final LangTag langTag) {

		ImmutablePair<String,LangTag> key = 
			new ImmutablePair<String,LangTag>(claimName, langTag);

		return userInfoClaims.remove(key);
	}


	/**
	 * Removes the specified UserInfo claims from the request, in all
	 * existing language tag variations.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
	 *
	 * @return The removed UserInfo claims, as an unmodifiable collection,
	 *         empty set if none were found.
	 */
	public Collection<Entry> removeUserInfoClaims(final String claimName) {

		Collection<Entry> removedClaims = new LinkedList<Entry>();

		Iterator<Map.Entry<ImmutablePair<String,LangTag>,Entry>> it = userInfoClaims.entrySet().iterator();

		while (it.hasNext()) {

			Map.Entry<ImmutablePair<String,LangTag>,Entry> reqEntry = it.next();

			if (reqEntry.getKey().getLeft().equals(claimName)) {

				removedClaims.add(reqEntry.getValue());

				it.remove();
			}
		}

		return Collections.unmodifiableCollection(removedClaims);
	}


	/**
	 * Returns the JSON object representation of this claims request.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "userinfo":
	 *    {
	 *     "given_name": {"essential": true},
	 *     "nickname": null,
	 *     "email": {"essential": true},
	 *     "email_verified": {"essential": true},
	 *     "picture": null,
	 *     "http://example.info/claims/groups": null
	 *    },
	 *   "id_token":
	 *    {
	 *     "auth_time": {"essential": true},
	 *     "acr": {"values": ["urn:mace:incommon:iap:silver"] }
	 *    }
	 * }
	 * </pre>
	 *
	 * @return The corresponding JSON object, empty if no ID token and 
	 *         UserInfo claims are specified.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();

		Collection<Entry> idTokenEntries = getIDTokenClaims();

		if (! idTokenEntries.isEmpty()) {

			o.put("id_token", Entry.toJSONObject(idTokenEntries));
		}

		Collection<Entry> userInfoEntries = getUserInfoClaims();

		if (! userInfoEntries.isEmpty()) {

			o.put("userinfo", Entry.toJSONObject(userInfoEntries));
		}

		return o;
	}


	@Override
	public String toString() {

		return toJSONObject().toString();
	}
	
	
	/**
	 * Resolves the claims request for the specified response type and
	 * scope. The scope values that are {@link OIDCScopeValue standard
	 * OpenID Connect scope values} are resolved to their respective
	 * individual claims requests, any other scope values are ignored.
	 *
	 * @param responseType The response type. Must not be {@code null}.
	 * @param scope        The scope. Must not be {@code null}.
	 * 
	 * @return The claims request.
	 */
	public static ClaimsRequest resolve(final ResponseType responseType, final Scope scope) {

		// Determine the claims target (ID token or UserInfo)
		final boolean switchToIDToken =
			responseType.contains(OIDCResponseTypeValue.ID_TOKEN) &&
			! responseType.contains(ResponseType.Value.CODE) &&
			! responseType.contains(ResponseType.Value.TOKEN);

		ClaimsRequest claimsRequest = new ClaimsRequest();
		
		for (Scope.Value value: scope) {
			
			Set<ClaimsRequest.Entry> entries;
			
			if (value.equals(OIDCScopeValue.PROFILE)) {
				
				entries = OIDCScopeValue.PROFILE.toClaimsRequestEntries();
				
			} else if (value.equals(OIDCScopeValue.EMAIL)) {
				
				entries = OIDCScopeValue.EMAIL.toClaimsRequestEntries();
				
			} else if (value.equals(OIDCScopeValue.PHONE)) {
				
				entries = OIDCScopeValue.PHONE.toClaimsRequestEntries();
				
			} else if (value.equals(OIDCScopeValue.ADDRESS)) {
				
				entries = OIDCScopeValue.ADDRESS.toClaimsRequestEntries();
				
			} else {
				
				continue; // skip
			}
			
			for (ClaimsRequest.Entry en: entries) {

				if (switchToIDToken)
					claimsRequest.addIDTokenClaim(en);
				else
					claimsRequest.addUserInfoClaim(en);
			}
		}
		
		return claimsRequest;
	}


	/**
	 * Resolves the merged claims request from the specified OpenID Connect
	 * authorisation request parameters. The scope values that are
	 * {@link OIDCScopeValue standard OpenID Connect scope values} are
	 * resolved to their respective individual claims requests, any other
	 * scope values are ignored.
	 *
	 * @param responseType  The response type. Must not be {@code null}.
	 * @param scope         The scope. Must not be {@code null}.
	 * @param claimsRequest The claims request, corresponding to the
	 *                      optional {@code claims} OpenID Connect
	 *                      authorisation request parameter, {@code null}
	 *                      if not specified.
	 *
	 * @return The merged claims request.
	 */
	public static ClaimsRequest resolve(final ResponseType responseType,
					    final Scope scope,
					    final ClaimsRequest claimsRequest) {

		ClaimsRequest mergedClaimsRequest = resolve(responseType, scope);

		mergedClaimsRequest.add(claimsRequest);

		return mergedClaimsRequest;
	}


	/**
	 * Resolves the merged claims request for the specified OpenID Connect
	 * authorisation request. The scope values that are
	 * {@link OIDCScopeValue standard OpenID Connect scope values} are
	 * resolved to their respective individual claims requests, any other
	 * scope values are ignored.
	 *
	 * @param authzRequest The OpenID Connect authorisation request. Must
	 *                     not be {@code null}.
	 *
	 * @return The merged claims request.
	 */
	public static ClaimsRequest resolve(final OIDCAuthorizationRequest authzRequest) {

		return resolve(authzRequest.getResponseType(), authzRequest.getScope(), authzRequest.getClaims());
	}


	/**
	 * Parses a claims request from the specified JSON object 
	 * representation. Unexpected members in the JSON object are silently
	 * ignored.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The claims request.
	 */
	public static ClaimsRequest parse(final JSONObject jsonObject) {

		ClaimsRequest claimsRequest = new ClaimsRequest();

		try {
			if (jsonObject.containsKey("id_token")) {

				JSONObject idTokenObject = (JSONObject)jsonObject.get("id_token");

				Collection<Entry> idTokenClaims = Entry.parseEntries(idTokenObject);

				for (Entry entry: idTokenClaims)
					claimsRequest.addIDTokenClaim(entry);
			}


			if (jsonObject.containsKey("userinfo")) {

				JSONObject userInfoObject = (JSONObject)jsonObject.get("userinfo");

				Collection<Entry> userInfoClaims = Entry.parseEntries(userInfoObject);

				for (Entry entry: userInfoClaims)
					claimsRequest.addUserInfoClaim(entry);
			}

		} catch (Exception e) {

			// Ignore
		}

		return claimsRequest;
	}
}
