package com.nimbusds.oauth2.sdk.assertions.saml2;


import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.assertions.AssertionDetails;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import net.jcip.annotations.Immutable;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.MapUtils;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;


/**
 * SAML 2.0 bearer assertion details for OAuth 2.0 client authentication and
 * authorisation grants.
 *
 * <p>Used for {@link com.nimbusds.oauth2.sdk.SAML2BearerGrant SAML 2.0 bearer
 * assertion grants}.
 *
 * <p>Example SAML 2.0 assertion:
 *
 * <pre>
 * &lt;Assertion IssueInstant="2010-10-01T20:07:34.619Z"
 *            ID="ef1xsbZxPV2oqjd7HTLRLIBlBb7"
 *            Version="2.0"
 *            xmlns="urn:oasis:names:tc:SAML:2.0:assertion"&gt;
 *     &lt;Issuer&gt;https://saml-idp.example.com&lt;/Issuer&gt;
 *     &lt;ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"&gt;
 *         [...omitted for brevity...]
 *     &lt;/ds:Signature&gt;
 *     &lt;Subject&gt;
 *         &lt;NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"&gt;
 *             brian@example.com
 *         &lt;/NameID&gt;
 *         &lt;SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"&gt;
 *             &lt;SubjectConfirmationData NotOnOrAfter="2010-10-01T20:12:34.619Z"
 *                                      Recipient="https://authz.example.net/token.oauth2"/&gt;
 *         &lt;/SubjectConfirmation&gt;
 *     &lt;/Subject&gt;
 *     &lt;Conditions&gt;
 *         &lt;AudienceRestriction&gt;
 *             &lt;Audience&gt;https://saml-sp.example.net&lt;/Audience&gt;
 *         &lt;/AudienceRestriction&gt;
 *     &lt;/Conditions&gt;
 *     &lt;AuthnStatement AuthnInstant="2010-10-01T20:07:34.371Z"&gt;
 *         &lt;AuthnContext&gt;
 *             &lt;AuthnContextClassRef&gt;urn:oasis:names:tc:SAML:2.0:ac:classes:X509&lt;/AuthnContextClassRef&gt;
 *         &lt;/AuthnContext&gt;
 *     &lt;/AuthnStatement&gt;
 * &lt;/Assertion&gt;
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Security Assertion Markup Language (SAML) 2.0 Profile for OAuth 2.0
 *         Client Authentication and Authorization Grants (RFC 7522), section
 *         3.
 * </ul>
 */
@Immutable
public class SAML2AssertionDetails extends AssertionDetails {


	/**
	 * The subject format (optional).
	 */
	private final String subjectFormat;


	/**
	 * The subject authentication time (optional).
	 */
	private final Date subjectAuthTime;


	/**
	 * The subject Authentication Context Class Reference (ACR) (optional).
	 */
	private final ACR subjectACR;
	

	/**
	 * The time before which this assertion must not be accepted for
	 * processing (optional).
	 */
	private final Date nbf;


	/**
	 * The client IPv4 or IPv6 address (optional).
	 */
	private final InetAddress clientAddress;


	/**
	 * The attribute statement (optional).
	 */
	private final Map<String,List<String>> attrStatement;


	/**
	 * Creates a new SAML 2.0 bearer assertion details instance. The
	 * expiration time is set to five minutes from the current system time.
	 * Generates a default identifier for the assertion. The issue time is
	 * set to the current system time.
	 *
	 * @param issuer   The issuer. Must not be {@code null}.
	 * @param subject  The subject. Must not be {@code null}.
	 * @param audience The audience, typically the URI of the authorisation
	 *                 server's token endpoint. Must not be {@code null}.
	 */
	public SAML2AssertionDetails(final Issuer issuer,
				     final Subject subject,
				     final Audience audience) {

		this(issuer, subject, null, null, null, audience.toSingleAudienceList(),
			new Date(new Date().getTime() + 5*60*1000L), null, new Date(),
			new Identifier(), null, null);
	}


	/**
	 * Creates a new SAML 2.0 bearer assertion details instance.
	 *
	 * @param issuer          The issuer. Must not be {@code null}.
	 * @param subject         The subject. Must not be {@code null}.
	 * @param subjectFormat   The subject format, {@code null} if not
	 *                        specified.
	 * @param subjectAuthTime The subject authentication time, {@code null}
	 *                        if not specified.
	 * @param subjectACR      The subject Authentication Context Class
	 *                        Reference (ACR), {@code null} if not
	 *                        specified.
	 * @param audience        The audience, typically including the URI of the
	 *                        authorisation server's token endpoint. Must not be
	 *                        {@code null}.
	 * @param exp             The expiration time. Must not be {@code null}.
	 * @param nbf             The time before which the assertion must not
	 *                        be accepted for processing, {@code null} if
	 *                        not specified.
	 * @param iat             The time at which the assertion was issued.
	 *                        Must not be {@code null}.
	 * @param id              Unique identifier for the assertion. Must not
	 *                        be {@code null}.
	 * @param clientAddress   The client address, {@code null} if not
	 *                        specified.
	 * @param attrStatement   The attribute statement (in simplified form),
	 *                        {@code null} if not specified.
	 */
	public SAML2AssertionDetails(final Issuer issuer,
				     final Subject subject,
				     final String subjectFormat,
				     final Date subjectAuthTime,
				     final ACR subjectACR,
				     final List<Audience> audience,
				     final Date exp,
				     final Date nbf,
				     final Date iat,
				     final Identifier id,
				     final InetAddress clientAddress,
				     final Map<String,List<String>> attrStatement) {

		super(issuer, subject, audience, iat, exp, id);

		if (iat == null) {
			throw new IllegalArgumentException("The issue time must not be null");
		}

		if (id == null) {
			throw new IllegalArgumentException("The assertion identifier must not be null");
		}

		this.subjectFormat = subjectFormat;
		this.subjectAuthTime = subjectAuthTime;
		this.subjectACR = subjectACR;
		this.clientAddress = clientAddress;
		this.nbf = nbf;
		this.attrStatement = attrStatement;
	}


	/**
	 * Returns the optional subject format.
	 *
	 * @return The subject format, {@code null} if not specified.
	 */
	public String getSubjectFormat() {
		return subjectFormat;
	}


	/**
	 * Returns the optional subject authentication time.
	 *
	 * @return The subject authentication time, {@code null} if not
	 *         specified.
	 */
	public Date getSubjectAuthenticationTime() {
		return subjectAuthTime;
	}


	/**
	 * Returns the optional subject Authentication Context Class Reference
	 * (ACR).
	 *
	 * @return The subject ACR, {@code null} if not specified.
	 */
	public ACR getSubjectACR() {
		return subjectACR;
	}


	/**
	 * Returns the optional not-before time.
	 *
	 * @return The not-before time, {@code null} if not specified.
	 */
	public Date getNotBeforeTime() {
		return nbf;
	}


	/**
	 * Returns the optional client address to which this assertion is
	 * bound.
	 *
	 * @return The client address, {@code null} if not specified.
	 */
	public InetAddress getClientInetAddress() {
		return clientAddress;
	}


	/**
	 * Returns the optional attribute statement.
	 *
	 * @return The attribute statement (in simplified form), {@code null}
	 *         if not specified.
	 */
	public Map<String, List<String>> getAttributeStatement() {
		return attrStatement;
	}


	/**
	 * Returns a SAML 2.0 assertion (unsigned) representation of this
	 * assertion details instance.
	 *
	 * @return The SAML 2.0 assertion (with no signature element).
	 *
	 * @throws SerializeException If serialisation failed.
	 */
	public Assertion toSAML2Assertion()
		throws SerializeException {

		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new SerializeException(e.getMessage(), e);
		}

		final XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

		// Top level assertion element
		SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);

		Assertion a = assertionBuilder.buildObject();
		a.setID(getID().getValue());
		a.setIssueInstant(new DateTime(getIssueTime()));

		// Issuer
		SAMLObjectBuilder<org.opensaml.saml2.core.Issuer> issuerBuilder = (SAMLObjectBuilder<org.opensaml.saml2.core.Issuer>) builderFactory.getBuilder(org.opensaml.saml2.core.Issuer.DEFAULT_ELEMENT_NAME);
		org.opensaml.saml2.core.Issuer iss = issuerBuilder.buildObject();
		iss.setValue(getIssuer().getValue());
		a.setIssuer(iss);

		// Conditions
		SAMLObjectBuilder<Conditions> conditionsBuilder = (SAMLObjectBuilder<Conditions>) builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
		Conditions conditions = conditionsBuilder.buildObject();

		// Audience restriction
		SAMLObjectBuilder<AudienceRestriction> audRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) builderFactory.getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
		AudienceRestriction audRestriction = audRestrictionBuilder.buildObject();

		// ... with single audience - the authz server
		SAMLObjectBuilder<org.opensaml.saml2.core.Audience> audBuilder = (SAMLObjectBuilder<org.opensaml.saml2.core.Audience>) builderFactory.getBuilder(org.opensaml.saml2.core.Audience.DEFAULT_ELEMENT_NAME);
		for (Audience audItem: getAudience()) {
			org.opensaml.saml2.core.Audience aud = audBuilder.buildObject();
			aud.setAudienceURI(audItem.getValue());
			audRestriction.getAudiences().add(aud);
		}
		conditions.getAudienceRestrictions().add(audRestriction);

		a.setConditions(conditions);


		// Subject elements
		SAMLObjectBuilder<org.opensaml.saml2.core.Subject> subBuilder = (SAMLObjectBuilder<org.opensaml.saml2.core.Subject>) builderFactory.getBuilder(org.opensaml.saml2.core.Subject.DEFAULT_ELEMENT_NAME);
		org.opensaml.saml2.core.Subject sub = subBuilder.buildObject();

		SAMLObjectBuilder<NameID> subIDBuilder = (SAMLObjectBuilder<NameID>) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		NameID nameID = subIDBuilder.buildObject();
		nameID.setFormat(subjectFormat);
		nameID.setValue(getSubject().getValue());
		sub.setNameID(nameID);

		SAMLObjectBuilder<SubjectConfirmation> subCmBuilder = (SAMLObjectBuilder<SubjectConfirmation>) builderFactory.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		SubjectConfirmation subCm = subCmBuilder.buildObject();
		subCm.setMethod(SubjectConfirmation.METHOD_BEARER);

		SAMLObjectBuilder<SubjectConfirmationData> subCmDataBuilder= (SAMLObjectBuilder<SubjectConfirmationData>) builderFactory.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		SubjectConfirmationData subCmData = subCmDataBuilder.buildObject();
		subCmData.setNotOnOrAfter(new DateTime(getExpirationTime()));
		subCmData.setNotBefore(getNotBeforeTime() != null ? new DateTime(getNotBeforeTime()) : null);
		subCmData.setRecipient(getAudience().get(0).getValue()); // recipient is single-valued

		if (clientAddress != null) {
			subCmData.setAddress(clientAddress.getHostAddress());
		}

		subCm.setSubjectConfirmationData(subCmData);

		sub.getSubjectConfirmations().add(subCm);

		a.setSubject(sub);

		// Auth time and class?
		if (subjectAuthTime != null || subjectACR != null) {

			SAMLObjectBuilder<AuthnStatement> authnStmtBuilder = (SAMLObjectBuilder<AuthnStatement>) builderFactory.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
			AuthnStatement authnStmt = authnStmtBuilder.buildObject();

			if (subjectAuthTime != null) {
				authnStmt.setAuthnInstant(new DateTime(subjectAuthTime));
			}

			if (subjectACR != null) {
				SAMLObjectBuilder<AuthnContext> authnCtxBuilder = (SAMLObjectBuilder<AuthnContext>) builderFactory.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
				AuthnContext authnCtx = authnCtxBuilder.buildObject();
				SAMLObjectBuilder<AuthnContextClassRef> acrBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) builderFactory.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
				AuthnContextClassRef acr = acrBuilder.buildObject();
				acr.setAuthnContextClassRef(subjectACR.getValue());
				authnCtx.setAuthnContextClassRef(acr);
				authnStmt.setAuthnContext(authnCtx);
			}

			a.getAuthnStatements().add(authnStmt);
		}

		// Attributes?
		if (MapUtils.isNotEmpty(attrStatement)) {

			SAMLObjectBuilder<AttributeStatement> attrContainerBuilder = (SAMLObjectBuilder<AttributeStatement>) builderFactory.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
			AttributeStatement attrSet = attrContainerBuilder.buildObject();

			SAMLObjectBuilder<Attribute> attrBuilder = (SAMLObjectBuilder<Attribute>) builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);

			for (Map.Entry<String,List<String>> entry: attrStatement.entrySet()) {

				Attribute attr = attrBuilder.buildObject();
				attr.setName(entry.getKey());

				XSStringBuilder stringBuilder = (XSStringBuilder) Configuration.getBuilderFactory().getBuilder(XSString.TYPE_NAME);

				for (String v: entry.getValue()) {
					XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
					stringValue.setValue(v);
					attr.getAttributeValues().add(stringValue);
				}

				attrSet.getAttributes().add(attr);
			}

			a.getAttributeStatements().add(attrSet);
		}

		return a;
	}


	/**
	 * Parses a SAML 2.0 bearer assertion details instance from the
	 * specified assertion object.
	 *
	 * @param assertion The assertion. Must not be {@code null}.
	 *
	 * @return The SAML 2.0 bearer assertion details.
	 *
	 * @throws ParseException If the assertion couldn't be parsed to a
	 *                        SAML 2.0 bearer assertion details instance.
	 */
	public static SAML2AssertionDetails parse(final Assertion assertion)
		throws ParseException {

		// Assertion > Issuer
		if (assertion.getIssuer() == null) {
			throw new ParseException("Missing Assertion Issuer element");
		}

		final Issuer issuer = new Issuer(assertion.getIssuer().getValue());

		// Assertion > Subject
		if (assertion.getSubject() == null) {
			throw new ParseException("Missing Assertion Subject element");
		}

		if (assertion.getSubject().getNameID() == null) {
			throw new ParseException("Missing Assertion Subject NameID element");
		}

		// Assertion > Subject > NameID
		final Subject subject = new Subject(assertion.getSubject().getNameID().getValue());

		// Assertion > Subject > NameID : Format
		final String subjectFormat = assertion.getSubject().getNameID().getFormat();

		// Assertion > AuthnStatement : AuthnInstant
		Date subjectAuthTime = null;

		// Assertion > AuthnStatement > AuthnContext > AuthnContextClassRef
		ACR subjectACR = null;

		if (CollectionUtils.isNotEmpty(assertion.getAuthnStatements())) {

			for (AuthnStatement authStmt: assertion.getAuthnStatements()) {

				if (authStmt == null) {
					continue; // skip
				}

				if (authStmt.getAuthnInstant() != null) {
					subjectAuthTime = authStmt.getAuthnInstant().toDate();
				}

				if (authStmt.getAuthnContext() != null && authStmt.getAuthnContext().getAuthnContextClassRef() != null) {
					subjectACR = new ACR(authStmt.getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef());
				}
			}
		}

		List<SubjectConfirmation> subCms = assertion.getSubject().getSubjectConfirmations();

		if (CollectionUtils.isEmpty(subCms)) {
			throw new ParseException("Missing SubjectConfirmation element");
		}

		// Assertion > Subject > SubjectConfirmation : Method
		boolean bearerMethodFound = false;
		for (SubjectConfirmation subCm: subCms) {
			if (SubjectConfirmation.METHOD_BEARER.equals(subCm.getMethod())) {
				bearerMethodFound = true;
				break;
			}
		}

		if (! bearerMethodFound) {
			throw new ParseException("Missing SubjectConfirmation Method " + SubjectConfirmation.METHOD_BEARER + " attribute");
		}

		Conditions conditions = assertion.getConditions();

		if (conditions == null) {
			throw new ParseException("Missing Conditions element");
		}

		List<AudienceRestriction> audRestrictions = conditions.getAudienceRestrictions();

		if (CollectionUtils.isEmpty(audRestrictions)) {
			throw new ParseException("Missing AudienceRestriction element");
		}

		// Assertion > Conditions > AudienceRestriction > Audience
		final Set<Audience> audSet = new HashSet<>(); // ensure no duplicates

		for (AudienceRestriction audRestriction: audRestrictions) {

			if (CollectionUtils.isEmpty(audRestriction.getAudiences())) {
				continue; // skip
			}

			for (org.opensaml.saml2.core.Audience aud: audRestriction.getAudiences()) {
				audSet.add(new Audience(aud.getAudienceURI()));
			}
		}

		// Optional recipient in
		// Assertion > Subject > SubjectConfirmation > SubjectConfirmationData
		for (SubjectConfirmation subCm: subCms) {

			if (subCm.getSubjectConfirmationData() == null) {
				continue; // skip
			}

			if (subCm.getSubjectConfirmationData().getRecipient() == null) {
				throw new ParseException("Missing SubjectConfirmationData Recipient attribute");
			}

			audSet.add(new Audience(subCm.getSubjectConfirmationData().getRecipient()));
		}

		// Set expiration and not-before times, try first in
		// Assertion > Conditions
		Date exp = conditions.getNotOnOrAfter() != null ? conditions.getNotOnOrAfter().toDate() : null;
		Date nbf = conditions.getNotBefore() != null ? conditions.getNotBefore().toDate() : null;
		if (exp == null) {
			// Try in Assertion > Subject > SubjectConfirmation > SubjectConfirmationData
			for (SubjectConfirmation subCm: subCms) {
				if (subCm.getSubjectConfirmationData() == null) {
					continue; // skip
				}

				exp = subCm.getSubjectConfirmationData().getNotOnOrAfter() != null ?
					subCm.getSubjectConfirmationData().getNotOnOrAfter().toDate()
					: null;

				nbf = subCm.getSubjectConfirmationData().getNotBefore() != null ?
					subCm.getSubjectConfirmationData().getNotBefore().toDate()
					: null;
			}
		}

		// Assertion : ID
		if (assertion.getID() == null) {
			throw new ParseException("Missing Assertion ID attribute");
		}

		final Identifier id = new Identifier(assertion.getID());

		// Assertion : IssueInstant
		if (assertion.getIssueInstant() == null) {
			throw new ParseException("Missing Assertion IssueInstant attribute");
		}

		final Date iat = assertion.getIssueInstant().toDate();

		// Assertion > Subject > SubjectConfirmation > SubjectConfirmationData > Address
		InetAddress clientAddress = null;

		for (SubjectConfirmation subCm: subCms) {
			if (subCm.getSubjectConfirmationData() != null && subCm.getSubjectConfirmationData().getAddress() != null) {
				try {
					clientAddress = InetAddress.getByName(subCm.getSubjectConfirmationData().getAddress());
				} catch (UnknownHostException e) {
					throw new ParseException("Invalid Address: " + e.getMessage(), e);
				}
			}
		}

		// Assertion > AttributeStatement > Attribute (: Name, > AttributeValue)
		Map<String,List<String>> attrStatement = null;

		if (CollectionUtils.isNotEmpty(assertion.getAttributeStatements())) {

			attrStatement = new HashMap<>();

			for (AttributeStatement attrStmt: assertion.getAttributeStatements()) {
				if (attrStmt == null) {
					continue; // skip
				}

				for (Attribute attr: attrStmt.getAttributes()) {
					String name = attr.getName();
					List<String> values = new LinkedList<>();
					for (XMLObject v: attr.getAttributeValues()) {
						values.add(v.getDOM().getTextContent());
					}
					attrStatement.put(name, values);
				}
			}
		}


		return new SAML2AssertionDetails(issuer, subject, subjectFormat, subjectAuthTime, subjectACR,
			new ArrayList<>(audSet), exp, nbf, iat, id, clientAddress, attrStatement);
	}
}
