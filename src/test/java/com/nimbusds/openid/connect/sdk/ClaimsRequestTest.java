package com.nimbusds.openid.connect.sdk;


import java.util.Collection;
import java.util.Set;

import com.nimbusds.oauth2.sdk.ResponseType;
import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;


/**
 * Tests the claims request class.
 *
 * @author Vladimir Dzhuvinov
 */
public class ClaimsRequestTest extends TestCase {
	
	
	private static boolean containsVoluntaryClaimsRequestEntry(final Collection<ClaimsRequest.Entry> entries, 
		                                                   final String claimName) {
		
		for (ClaimsRequest.Entry en: entries) {
			
			if (en.getClaimName().equals(claimName) &&
			    en.getClaimRequirement().equals(ClaimRequirement.VOLUNTARY) &&
			    en.getLangTag() == null &&
			    en.getValue() == null &&
			    en.getValues() == null)
				
				return true;
		}
		
		return false;
	}
	
	
	private static boolean containsEssentialClaimsRequestEntry(final Collection<ClaimsRequest.Entry> entries, 
		                                                   final String claimName) {
		
		for (ClaimsRequest.Entry en: entries) {
			
			if (en.getClaimName().equals(claimName) &&
			    en.getClaimRequirement().equals(ClaimRequirement.ESSENTIAL) &&
			    en.getLangTag() == null &&
			    en.getValue() == null &&
			    en.getValues() == null)
				
				return true;
		}
		
		return false;
	}


	public void testResolveSimple()
		throws Exception {

		Scope scope = Scope.parse("openid");

		ClaimsRequest cr = ClaimsRequest.resolve(ResponseType.parse("code"), scope);

		System.out.println("Claims request for scope openid: " + cr.toJSONObject());

		assertTrue(cr.getIDTokenClaims().isEmpty());
		assertTrue(cr.getUserInfoClaims().isEmpty());
	}
	
	
	public void testResolveToUserInfo()
		throws Exception {
		
		Scope scope = Scope.parse("openid email profile phone address");
		
		ClaimsRequest cr = ClaimsRequest.resolve(ResponseType.parse("code"), scope);
		
		System.out.println("Claims request for scope openid email profile phone address: " + cr.toJSONObject());
		
		assertTrue(cr.getIDTokenClaims().isEmpty());
		
		Collection<ClaimsRequest.Entry> userInfoClaims = cr.getUserInfoClaims();
		
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email_verified"));
		
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "given_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "family_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "middle_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "nickname"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "preferred_username"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "profile"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "picture"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "website"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "gender"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "birthdate"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "zoneinfo"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "locale"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "updated_at"));
		
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "phone_number"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "phone_number_verified"));
		
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "address"));
		
		assertEquals(19, userInfoClaims.size());
		
		Set<String> claimNames = cr.getIDTokenClaimNames(false);
		assertTrue(claimNames.isEmpty());
		
		claimNames = cr.getUserInfoClaimNames(false);
		
		assertTrue(claimNames.contains("email"));
		assertTrue(claimNames.contains("email_verified"));
		assertTrue(claimNames.contains("name"));
		assertTrue(claimNames.contains("given_name"));
		assertTrue(claimNames.contains("family_name"));
		assertTrue(claimNames.contains("middle_name"));
		assertTrue(claimNames.contains("nickname"));
		assertTrue(claimNames.contains("preferred_username"));
		assertTrue(claimNames.contains("profile"));
		assertTrue(claimNames.contains("picture"));
		assertTrue(claimNames.contains("website"));
		assertTrue(claimNames.contains("gender"));
		assertTrue(claimNames.contains("birthdate"));
		assertTrue(claimNames.contains("zoneinfo"));
		assertTrue(claimNames.contains("locale"));
		assertTrue(claimNames.contains("updated_at"));
		assertTrue(claimNames.contains("phone_number"));
		assertTrue(claimNames.contains("phone_number_verified"));
		assertTrue(claimNames.contains("address"));
		
		assertEquals(19, claimNames.size());
	}


	public void testResolveToIDToken()
		throws Exception {

		Scope scope = Scope.parse("openid email profile phone address");

		ClaimsRequest cr = ClaimsRequest.resolve(ResponseType.parse("id_token"), scope);

		System.out.println("Claims request for scope openid email profile phone address: " + cr.toJSONObject());

		assertTrue(cr.getUserInfoClaims().isEmpty());

		Collection<ClaimsRequest.Entry> idTokenClaims = cr.getIDTokenClaims();

		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "email"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "email_verified"));

		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "given_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "family_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "middle_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "nickname"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "preferred_username"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "profile"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "picture"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "website"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "gender"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "birthdate"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "zoneinfo"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "locale"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "updated_at"));

		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "phone_number"));
		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "phone_number_verified"));

		assertTrue(containsVoluntaryClaimsRequestEntry(idTokenClaims, "address"));

		assertEquals(19, idTokenClaims.size());

		Set<String> claimNames = cr.getUserInfoClaimNames(false);
		assertTrue(claimNames.isEmpty());

		claimNames = cr.getIDTokenClaimNames(false);

		assertTrue(claimNames.contains("email"));
		assertTrue(claimNames.contains("email_verified"));
		assertTrue(claimNames.contains("name"));
		assertTrue(claimNames.contains("given_name"));
		assertTrue(claimNames.contains("family_name"));
		assertTrue(claimNames.contains("middle_name"));
		assertTrue(claimNames.contains("nickname"));
		assertTrue(claimNames.contains("preferred_username"));
		assertTrue(claimNames.contains("profile"));
		assertTrue(claimNames.contains("picture"));
		assertTrue(claimNames.contains("website"));
		assertTrue(claimNames.contains("gender"));
		assertTrue(claimNames.contains("birthdate"));
		assertTrue(claimNames.contains("zoneinfo"));
		assertTrue(claimNames.contains("locale"));
		assertTrue(claimNames.contains("updated_at"));
		assertTrue(claimNames.contains("phone_number"));
		assertTrue(claimNames.contains("phone_number_verified"));
		assertTrue(claimNames.contains("address"));

		assertEquals(19, claimNames.size());
	}


	public void testResolveDependingOnResponseType()
		throws Exception {

		Scope scope = Scope.parse("openid email");

		ClaimsRequest cr = ClaimsRequest.resolve(ResponseType.parse("id_token code"), scope);

		assertTrue(cr.getIDTokenClaims().isEmpty());

		Collection<ClaimsRequest.Entry> userInfoClaims = cr.getUserInfoClaims();
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email_verified"));

		cr = ClaimsRequest.resolve(ResponseType.parse("id_token token"), scope);

		assertTrue(cr.getIDTokenClaims().isEmpty());

		userInfoClaims = cr.getUserInfoClaims();
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email_verified"));
	}
	
	
	public void testAdd()
		throws Exception {
		
		Scope scope = Scope.parse("openid profile");
		
		ClaimsRequest cr = ClaimsRequest.resolve(ResponseType.parse("code"), scope);

		System.out.println("Claims request for scope openid profile: " + cr.toJSONObject());
		
		assertTrue(cr.getIDTokenClaims().isEmpty());
		
		Collection<ClaimsRequest.Entry> userInfoClaims = cr.getUserInfoClaims();
		
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "given_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "family_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "middle_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "nickname"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "preferred_username"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "profile"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "picture"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "website"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "gender"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "birthdate"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "zoneinfo"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "locale"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "updated_at"));
		
		assertEquals(14, userInfoClaims.size());
		
		
		ClaimsRequest addon = new ClaimsRequest();
		addon.addUserInfoClaim("email", ClaimRequirement.ESSENTIAL);
		addon.addUserInfoClaim("email_verified", ClaimRequirement.ESSENTIAL);
		
		System.out.println("Essential claims request: " + addon.toJSONObject());
		
		cr.add(addon);
		
	
		assertTrue(containsEssentialClaimsRequestEntry(userInfoClaims, "email"));
		assertTrue(containsEssentialClaimsRequestEntry(userInfoClaims, "email_verified"));
		
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "given_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "family_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "middle_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "nickname"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "preferred_username"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "profile"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "picture"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "website"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "gender"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "birthdate"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "zoneinfo"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "locale"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "updated_at"));
		
		assertEquals(16, userInfoClaims.size());
		
		
		Set<String> claimNames = cr.getIDTokenClaimNames(false);
		assertTrue(claimNames.isEmpty());
		
		claimNames = cr.getUserInfoClaimNames(false);
		
		assertTrue(claimNames.contains("email"));
		assertTrue(claimNames.contains("email_verified"));
		assertTrue(claimNames.contains("name"));
		assertTrue(claimNames.contains("given_name"));
		assertTrue(claimNames.contains("family_name"));
		assertTrue(claimNames.contains("middle_name"));
		assertTrue(claimNames.contains("nickname"));
		assertTrue(claimNames.contains("preferred_username"));
		assertTrue(claimNames.contains("profile"));
		assertTrue(claimNames.contains("picture"));
		assertTrue(claimNames.contains("website"));
		assertTrue(claimNames.contains("gender"));
		assertTrue(claimNames.contains("birthdate"));
		assertTrue(claimNames.contains("zoneinfo"));
		assertTrue(claimNames.contains("locale"));
		assertTrue(claimNames.contains("updated_at"));
		
		assertEquals(16, claimNames.size());
	}
}