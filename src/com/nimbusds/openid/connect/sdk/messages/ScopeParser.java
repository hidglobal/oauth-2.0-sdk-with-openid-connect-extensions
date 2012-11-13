package com.nimbusds.openid.connect.sdk.messages;


import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.openid.connect.sdk.ParseException;


/**
 * Parser for {@link ScopeToken}s. This class is immutable.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-13)
 */
@Immutable
public class ScopeParser {


	/**
	 * Parser instance for standard scope tokens (thread-safe).
	 */
	protected static final ScopeParser STD_SCOPE_PARSER = new ScopeParser();
	

	/**
	 * Map of scope value strings to their corresponding object.
	 */
	private final Map<String,ScopeToken> map = new HashMap<String,ScopeToken>();
	
	
	/**
	 * Creates a new parser for standard scope tokens.
	 *
	 * <p>Supports all standard OpenID Connect scope tokens:
	 *
	 * <ul>
	 *     <li>ScopeToken#OPENID,
	 *     <li>ScopeToken#PROFILE
	 *     <li>ScopeToken#EMAIL
	 *     <li>ScopeToken#ADDRESS
	 *     <li>ScopeToken#PHONE
	 * </ul>
	 */
	public ScopeParser() {
	
		this(ScopeToken.OPENID,
		     ScopeToken.PROFILE,
		     ScopeToken.EMAIL,
		     ScopeToken.ADDRESS,
		     ScopeToken.PHONE);
	}
	
	
	/**
	 * Creates a new parser for the specified scope tokens.
	 *
	 * @param tokens The scope tokens to parse.
	 */
	public ScopeParser(final ScopeToken... tokens) {
	
		for (ScopeToken t: tokens)
			map.put(t.toString(), t);
	}
	
	
	/**
	 * Returns the scope tokens configured for parsing.
	 *
	 * @return The scope tokens for parsing.
	 */
	public Collection<ScopeToken> getValues() {
	
		return map.values();
	}
	
	
	/**
	 * Parses a {@code Scope} from the specified string. Unexpected scope
	 * tokens are ignored. For strict parsing see {@link #parseStrict}.
	 *
	 * @param s A string containing one or more scope tokens delimited by 
	 *          space.
	 *
	 * @return The parsed scope.
	 */
	public Scope parse(final String s) {
	
		Scope scope = new Scope();
	
		String[] tokens = s.split("\\s+");
		
		for (String t: tokens) {
		
			if (map.containsKey(t))
				scope.add(map.get(t));
		}
		
		return scope;
	}
	
	
	/**
	 * Parses a {@code Scope} from the specified string.
	 *
	 * @param s A string containing one or more scope tokens delimited by 
	 *          space.
	 *
	 * @return The parsed scope.
	 *
	 * @throws ParseException If an unexpected scope token is encountered
	 *                        or a {@link ScopeToken#OPENID} is missing.
	 */
	public Scope parseStrict(final String s)
		throws ParseException {
		
		Scope scope = new Scope();
		
		String[] tokens = s.split("\\s+");
		
		for (String t: tokens) {
		
			if (map.containsKey(t))
				scope.add(map.get(t));
			else
				throw new ParseException("Unexpected scope token: " + t);
		}
		
		if (! scope.isValid())
			throw new ParseException("Invalid scope: Missing mandatory \"openid\" scope token");
		
		return scope;
	}
}
