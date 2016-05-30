package com.nimbusds.openid.connect.sdk.id;


import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;


/**
 * Sector identifier URI validator.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 8.1.
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 5.
 * </ul>
 */
public class SectorIDURIValidator {
	

	/**
	 * The URL resource retriever.
	 */
	private final ResourceRetriever resourceRetriever;


	/**
	 * Creates a new sector identifier URI validator.
	 *
	 * @param resourceRetriever The URL resource retriever to use. Must not
	 *                          be {@code null}.
	 */
	public SectorIDURIValidator(final ResourceRetriever resourceRetriever) {
		if (resourceRetriever == null) {
			throw new IllegalArgumentException("The resource retriever must not be null");
		}
		this.resourceRetriever = resourceRetriever;
	}


	/**
	 * Returns the URL resource retriever.
	 *
	 * @return The resource retriever.
	 */
	public ResourceRetriever getResourceRetriever() {
		return resourceRetriever;
	}


	/**
	 * Validates the specified sector identifier URI by ensuring it lists
	 * all specified redirection URIs.
	 *
	 *
	 * @param sectorURI    The sector identifier URI. Must not be
	 *                     {@code null}.
	 * @param redirectURIs The redirection URIs of the client. Must not be
	 *                     {@code null}.
	 *
	 * @throws GeneralException If validation failed.
	 */
	public void validate(final URI sectorURI, final Set<URI> redirectURIs)
		throws GeneralException {

		Resource resource;

		try {
			resource = resourceRetriever.retrieveResource(sectorURI.toURL());
		} catch (IOException e) {
			throw new GeneralException("Couldn't retrieve the sector ID JSON document: " + e.getMessage(), e);
		}

		if (resource.getContentType() == null) {
			throw new GeneralException("Couldn't validate sector ID URI: Missing Content-Type");
		}

		if (! resource.getContentType().toLowerCase().startsWith("application/json")) {
			throw new GeneralException("Couldn't validate sector ID URI: Content-Type must be application/json, found " + resource.getContentType());
		}

		List<URI> uriList = JSONArrayUtils.toURIList(JSONArrayUtils.parse(resource.getContent()));

		for (URI uri: redirectURIs) {

			if (! uriList.contains(uri)) {
				throw new GeneralException("Sector ID URI validation failed: Redirect URI " + uri + " is missing from published JSON array at sector ID URI " + sectorURI);
			}
		}
	}
}
