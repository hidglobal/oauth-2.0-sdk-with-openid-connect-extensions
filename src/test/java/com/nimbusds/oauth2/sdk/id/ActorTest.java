package com.nimbusds.oauth2.sdk.id;


import com.nimbusds.oauth2.sdk.ParseException;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


public class ActorTest extends TestCase {
	

	public void testMinimalConstructor()
		throws ParseException {

		Actor actor = new Actor(new Subject("claire"));
		assertEquals("claire", actor.getSubject().getValue());
		assertNull(actor.getIssuer());
		assertNull(actor.getParent());

		JSONObject jsonObject = actor.toJSONObject();
		assertEquals("claire", jsonObject.get("sub"));
		assertEquals(1, jsonObject.size());

		actor = Actor.parse(jsonObject);
		assertEquals("claire", actor.getSubject().getValue());
		assertNull(actor.getIssuer());
		assertNull(actor.getParent());

		// top-level JSON object
		JSONObject topLevel = new JSONObject();
		topLevel.put("act", actor.toJSONObject());

		actor = Actor.parseTopLevel(topLevel);
		assertEquals("claire", actor.getSubject().getValue());
		assertNull(actor.getIssuer());
		assertNull(actor.getParent());
	}


	public void testFullConstructor()
		throws ParseException {

		Actor parent = new Actor(new Subject("cindy"));

		Actor actor = new Actor(new Subject("claire"), new Issuer("https://openid.c2id.com"), parent);
		assertEquals("claire", actor.getSubject().getValue());
		assertEquals("https://openid.c2id.com", actor.getIssuer().getValue());
		assertEquals(parent, actor.getParent());

		JSONObject jsonObject = actor.toJSONObject();
		assertEquals("claire", jsonObject.get("sub"));
		assertEquals("https://openid.c2id.com", jsonObject.get("iss"));
		assertEquals("cindy", ((JSONObject)jsonObject.get("act")).get("sub"));
		assertEquals(3, jsonObject.size());

		actor = Actor.parse(jsonObject);
		assertEquals("claire", actor.getSubject().getValue());
		assertEquals("https://openid.c2id.com", actor.getIssuer().getValue());
		assertEquals("cindy", actor.getParent().getSubject().getValue());
		assertNull(actor.getParent().getIssuer());
		assertNull(actor.getParent().getParent());

		// top-level JSON object
		JSONObject topLevel = new JSONObject();
		topLevel.put("act", actor.toJSONObject());

		actor = Actor.parseTopLevel(topLevel);
		assertEquals("claire", actor.getSubject().getValue());
		assertEquals("https://openid.c2id.com", actor.getIssuer().getValue());
		assertEquals("cindy", actor.getParent().getSubject().getValue());
		assertNull(actor.getParent().getIssuer());
		assertNull(actor.getParent().getParent());
	}


	public void testParseEmptyTopLevel()
		throws ParseException {

		JSONObject jsonObject = new JSONObject();

		assertNull(Actor.parseTopLevel(jsonObject));
	}


	public void testEquality() {

		assertTrue(new Actor(new Subject("claire")).equals(new Actor(new Subject("claire"))));

		assertTrue(new Actor(new Subject("claire"), new Issuer("https://openid.com"), null)
			.equals(new Actor(new Subject("claire"), new Issuer("https://openid.com"), null)));

		assertTrue(new Actor(new Subject("claire"), new Issuer("https://openid.com"), new Actor(new Subject("cindy")))
			.equals(new Actor(new Subject("claire"), new Issuer("https://openid.com"), new Actor(new Subject("cindy")))));
	}
}
