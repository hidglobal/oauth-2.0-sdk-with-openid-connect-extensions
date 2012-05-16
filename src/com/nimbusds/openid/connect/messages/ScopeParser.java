package com.nimbusds.openid.connect.messages;


import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.nimbusds.openid.connect.ParseException;


/**
 * Parser for {@link ScopeMember}s.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-04-22)
 */
public class ScopeParser {


	/**
	 * Parser instance for {@link StdScopeMember standard scope member}
	 * (thread-safe).
	 */
	protected static final ScopeParser STD_SCOPE_PARSER = new ScopeParser();
	

	/**
	 * Map of scope value strings to their corresponding object.
	 */
	private Map<String,ScopeMember> map = new HashMap<String,ScopeMember>();
	
	
	/**
	 * Creates a new parser for the {@link StdScopeMember standard scope
	 * members}.
	 */
	public ScopeParser() {
	
		this(StdScopeMember.values());
	}
	
	
	/**
	 * Creates a new parser for the specified scope members.
	 *
	 * @param members The scope members to parse.
	 */
	public ScopeParser(final ScopeMember... members) {
	
		for (ScopeMember m: members)
			map.put(m.toString(), m);
	}
	
	
	/**
	 * Returns the scope members configured for parsing.
	 *
	 * @return The scope members for parsing.
	 */
	public Collection<ScopeMember> getValues() {
	
		return map.values();
	}
	
	
	/**
	 * Parses a {@code Scope} from the specified string. Unexpected scope
	 * members are ignored. For strict parsing see {@link #parseStrict}.
	 *
	 * @param s A string containing one or more scope members delimited by 
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
	 * @param s A string containing one or more scope members delimited by 
	 *          space.
	 *
	 * @return The parsed scope.
	 *
	 * @throws ParseException If an unexpected scope member is encountered
	 *                        or a {@link StdScopeMember#OPENID} is missing.
	 */
	public Scope parseStrict(final String s)
		throws ParseException {
		
		Scope scope = new Scope();
		
		String[] tokens = s.split("\\s+");
		
		for (String t: tokens) {
		
			if (map.containsKey(t))
				scope.add(map.get(t));
			else
				throw new ParseException("Couldn't parse scope: Unexpected scope member: " + t);
		}
		
		if (! scope.isValid())
			throw new ParseException("Couldn't parse scope: Missing \"openid\" scope member");
		
		return scope;
	}
}
