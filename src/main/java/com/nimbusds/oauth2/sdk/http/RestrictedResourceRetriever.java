package com.nimbusds.oauth2.sdk.http;


/**
 * Retriever of resources specified by URL which permits setting of HTTP
 * connect and read timeouts as well as a size limit.
 */
public interface RestrictedResourceRetriever extends ResourceRetriever {
	

	/**
	 * Gets the HTTP connect timeout.
	 *
	 * @return The HTTP connect timeout, in milliseconds, zero for
	 *         infinite.
	 */
	int getConnectTimeout();


	/**
	 * Sets the HTTP connect timeout.
	 *
	 * @param connectTimeout The HTTP connect timeout, in milliseconds,
	 *                       zero for infinite. Must not be negative.
	 */
	void setConnectTimeout(final int connectTimeout);


	/**
	 * Gets the HTTP read timeout.
	 *
	 * @return The HTTP read timeout, in milliseconds, zero for infinite.
	 */
	int getReadTimeout();


	/**
	 * Sets the HTTP read timeout.
	 *
	 * @param readTimeout The HTTP read timeout, in milliseconds, zero for
	 *                    infinite. Must not be negative.
	 */
	void setReadTimeout(final int readTimeout);


	/**
	 * Gets the HTTP entity size limit.
	 *
	 * @return The HTTP entity size limit, in bytes, zero for infinite.
	 */
	int getSizeLimit();


	/**
	 * Sets the HTTP entity size limit.
	 *
	 * @param sizeLimit The HTTP entity size limit, in bytes, zero for
	 *                  infinite. Must not be negative.
	 */
	void setSizeLimit(int sizeLimit);
}
