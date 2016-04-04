package com.nimbusds.oauth2.sdk.id;


import java.io.Serializable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;


/**
 * Authorised actor in impersonation and delegation cases.
 */
@Immutable
public final class Actor implements Serializable, Comparable<Actor>, JSONAware {
	

	/**
	 * The actor subject.
	 */
	private final Subject subject;


	/**
	 * Optional issuer for the actor subject.
	 */
	private final Issuer issuer;


	/**
	 * Optional parent for the actor.
	 */
	private final Actor parent;


	/**
	 * Creates a new actor.
	 *
	 * @param subject The subject. Must not be {@code null}.
	 */
	public Actor(final Subject subject) {
		this(subject, null, null);
	}


	/**
	 * Creates a new actor.
	 *
	 * @param subject The subject. Must not be {@code null}.
	 * @param issuer  Optional issuer for the subject, {@code null} if
	 *                not specified.
	 * @param parent  Optional parent for the actor, {@code null} if none.
	 */
	public Actor(final Subject subject, final Issuer issuer, final Actor parent) {
		if (subject == null) {
			throw new IllegalArgumentException("The subject must not be null");
		}
		this.subject = subject;
		this.issuer = issuer;
		this.parent = parent;
	}


	/**
	 * Returns the subject.
	 *
	 * @return The subject.
	 */
	public Subject getSubject() {
		return subject;
	}


	/**
	 * Returns the optional issuer for the subject.
	 *
	 * @return The issuer, {@code null} if not specified.
	 */
	public Issuer getIssuer() {
		return issuer;
	}


	/**
	 * Returns the optional parent for this actor.
	 *
	 * @return The optional parent for the actor, {@code null} if none.
	 */
	public Actor getParent() {
		return parent;
	}


	/**
	 * Returns a JSON object representation of this actor.
	 *
	 * <p>Simple example:
	 *
	 * <pre>
	 * {
	 *   "sub" : "admin@example.com"
	 * }
	 * </pre>
	 *
	 * <p>With nesting:
	 *
	 * <pre>
	 * {
	 *   "sub" : "consumer.example.com-web-application",
	 *   "iss" : "https://issuer.example.net",
	 *   "act" : { "sub":"admin@example.com" }
	 * }
	 * </pre>
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();
		o.put("sub", subject.getValue());

		if (issuer != null) {
			o.put("iss", issuer.getValue());
		}

		if (parent != null) {
			o.put("act", parent.toJSONObject());
		}

		return o;
	}


	@Override
	public int compareTo(final Actor other) {

		return toJSONString().compareTo(other.toJSONString());
	}


	@Override
	public String toJSONString() {
		return toJSONObject().toJSONString();
	}


	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof Actor)) return false;

		Actor actor = (Actor) o;

		if (!subject.equals(actor.subject)) return false;
		if (issuer != null ? !issuer.equals(actor.issuer) : actor.issuer != null)
			return false;
		return parent != null ? parent.equals(actor.parent) : actor.parent == null;

	}


	@Override
	public int hashCode() {
		int result = subject.hashCode();
		result = 31 * result + (issuer != null ? issuer.hashCode() : 0);
		result = 31 * result + (parent != null ? parent.hashCode() : 0);
		return result;
	}


	/**
	 * Parses an actor from the specified JSON object representation.
	 *
	 * <p>Simple example:
	 *
	 * <pre>
	 * {
	 *   "sub" : "admin@example.com"
	 * }
	 * </pre>
	 *
	 * <p>With nesting:
	 *
	 * <pre>
	 * {
	 *   "sub" : "consumer.example.com-web-application",
	 *   "iss" : "https://issuer.example.net",
	 *   "act" : { "sub":"admin@example.com" }
	 * }
	 * </pre>
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The actor.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static Actor parse(final JSONObject jsonObject)
		throws ParseException {

		Subject sub = new Subject(JSONObjectUtils.getString(jsonObject, "sub"));

		Issuer iss = null;

		if (jsonObject.containsKey("iss")) {
			iss = new Issuer(JSONObjectUtils.getString(jsonObject, "iss"));
		}

		Actor parent = parseTopLevel(jsonObject);

		return new Actor(sub, iss, parent);
	}


	/**
	 * Parses an actor from the specified top-level JSON object contains
	 * an optional actor JSON representation.
	 *
	 * <p>Simple example:
	 *
	 * <pre>
	 * {
	 *   "aud" : "https://consumer.example.com",
	 *   "iss" : "https://issuer.example.com",
	 *   "exp" : 1443904177,
	 *   "nbf" : 1443904077,
	 *   "sub" : "user@example.com",
	 *   "act" : { "sub" : "admin@example.com" }
	 * }
	 * </pre>
	 *
	 * <p>With nesting:
	 * {
	 *   "aud" : "https://backend.example.com",
	 *   "iss" : "https://issuer.example.com",
	 *   "exp" : 1443904100,
	 *   "nbf" : 1443904000,
	 *   "sub" : "user@example.com",
	 *   "act" : { "sub" : "consumer.example.com-web-application",
	 *             "iss" : "https://issuer.example.net",
	 *             "act" : { "sub":"admin@example.com" } }
	 * }
	 * <pre>
	 *
	 * </pre>
	 *
	 * @param jsonObject The top-level JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The actor, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static Actor parseTopLevel(final JSONObject jsonObject)
		throws ParseException {

		if (! jsonObject.containsKey("act")) {
			return null;
		}

		return parse(JSONObjectUtils.getJSONObject(jsonObject, "act"));
	}
}
