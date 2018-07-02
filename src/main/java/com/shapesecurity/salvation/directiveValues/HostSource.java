package com.shapesecurity.salvation.directiveValues;

import com.shapesecurity.salvation.Constants;
import com.shapesecurity.salvation.data.GUID;
import com.shapesecurity.salvation.data.Origin;
import com.shapesecurity.salvation.data.SchemeHostPortTriple;
import com.shapesecurity.salvation.data.URI;
import com.shapesecurity.salvation.interfaces.MatchesSource;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;


public class HostSource implements SourceExpression, AncestorSource, MatchesSource {
	public static final HostSource WILDCARD = new HostSource(null, "*", Constants.EMPTY_PORT, null);
	private static final int WILDCARD_HASHCODE = 0x9F4E3EEA;
	@Nullable
	private final String scheme;
	@Nonnull
	private final String host;
	private final int port;
	@Nullable
	private final String path;

	public boolean hasPath() {
		return (this.path != null) && !this.path.isEmpty();
	}

	public HostSource(@Nullable String scheme, @Nonnull String host, int port, @Nullable String path) {
		this.scheme = scheme;
		this.host = host;
		this.port = port;
		this.path = path != null ? path.replaceAll(";", "%3B").replaceAll(",", "%2C") : null;
	}

	@Override
	public boolean equals(@Nullable Object other) {
		if (other == null || !(other instanceof HostSource)) {
			return false;
		}
		HostSource otherPrime = (HostSource) other;
		if (this.isWildcard() && otherPrime.isWildcard()) {
			return true;
		}

		// safe to do uniform comparison of scheme and host
		return Objects.equals(this.scheme != null ? this.scheme.toLowerCase() : null,
				otherPrime.scheme != null ? otherPrime.scheme.toLowerCase() : null) &&
				Objects.equals(this.host != null ? this.host.toLowerCase() : null,
						otherPrime.host != null ? otherPrime.host.toLowerCase() : null) &&
				this.port == otherPrime.port &&
				Objects.equals(this.path, otherPrime.path);
	}

	@Override
	public int hashCode() {

		// scheme and host matching is case-insensitive
		int h = 0;
		if (this.scheme != null) {
			h ^= this.scheme.toLowerCase().hashCode() ^ 0xA303EFA3;
		}
		h ^= this.host.toLowerCase().hashCode() ^ 0xFB2290B2;
		h ^= this.port ^ 0xB54E99F3;
		if (this.path != null) {
			h ^= this.path.hashCode() ^ 0x13324C0E;
		}
		return h;
	}

	public boolean isWildcard() {
		return this.host.equals("*") && this.scheme == null && this.port == Constants.EMPTY_PORT && this.path == null;
	}

	public static boolean hostMatches(@Nonnull String hostA, @Nonnull String hostB) {
		if (hostA.startsWith("*")) {
			String remaining = hostA.substring(1);
			if (hostB.toLowerCase().endsWith(remaining.toLowerCase())) {
				return true;
			} else {
				return false;
			}
		}

		if (!hostA.equalsIgnoreCase(hostB)) {
			return false;
		}

		Matcher IPv4Matcher = Constants.IPv4address.matcher(hostA);
		Matcher IPv6Matcher = Constants.IPv6addressWithOptionalBracket.matcher(hostA);
		Matcher IPv6LoopbackMatcher = Constants.IPV6loopback.matcher(hostA);
		if ((IPv4Matcher.find() && !hostA.equals("127.0.0.1")) || IPv6Matcher.find() || IPv6LoopbackMatcher.find()) {
			return false;
		}
		return true;

	}

	@Override
	public boolean matchesSource(@Nonnull Origin origin, @Nonnull GUID resource) {
		String originScheme = null;
		if (origin instanceof GUID) {
			originScheme = ((GUID) origin).scheme();
		}
		String resourceScheme = resource.scheme();
		if (origin instanceof GUID && originScheme != null && resourceScheme != null) {
			return originScheme.equalsIgnoreCase(resourceScheme);
		} else {
			return false;
		}
	}

	@Override
	public boolean matchesSource(@Nonnull Origin origin, @Nonnull URI resource) {
		if (origin instanceof GUID) {
			// wildcard matches a network scheme
			return this.isWildcard() && resource.isNetworkScheme();
		} else if (!(origin instanceof SchemeHostPortTriple)) {
			return false;
		}
		SchemeHostPortTriple shpOrigin = (SchemeHostPortTriple) origin;
		if (this.isWildcard()) {
			return resource.isNetworkScheme() || shpOrigin.scheme.matches(resource.scheme);
		}
		boolean schemeMatches;
		if (this.scheme == null) {
			schemeMatches = SchemeHostPortTriple.matchesSecureScheme(shpOrigin.scheme, resource.scheme);
		} else {
			schemeMatches = SchemeHostPortTriple.matchesSecureScheme(this.scheme, resource.scheme);
		}
		boolean hostMatches = hostMatches(this.host, resource.host);
		boolean uriUsesDefaultPort = resource.port == Constants.EMPTY_PORT
				|| SchemeHostPortTriple.defaultPortForProtocol(resource.scheme) == resource.port;
		boolean thisUsesDefaultPort = this.scheme != null && (this.port == Constants.EMPTY_PORT
				|| SchemeHostPortTriple.defaultPortForProtocol(this.scheme) == this.port);
		boolean portMatches = this.port == Constants.WILDCARD_PORT || (thisUsesDefaultPort && uriUsesDefaultPort) ||
				(this.port == Constants.EMPTY_PORT ?
						uriUsesDefaultPort :
						(resource.port == Constants.EMPTY_PORT ? thisUsesDefaultPort : this.port == resource.port));
		boolean pathMatches = pathMatches(this.path, resource.path);

		return schemeMatches && hostMatches && portMatches && pathMatches;
	}

	public boolean matchesOnlyOrigin(@Nonnull SchemeHostPortTriple origin) {
		boolean schemeMatches = this.scheme != null && this.scheme.equalsIgnoreCase(origin.scheme);
		boolean hostMatches = this.host.equalsIgnoreCase(origin.host);
		boolean originUsesDefaultPort = origin.port == Constants.EMPTY_PORT
				|| SchemeHostPortTriple.defaultPortForProtocol(origin.scheme) == origin.port;
		boolean thisUsesDefaultPort = this.scheme != null && (this.port == Constants.EMPTY_PORT
				|| SchemeHostPortTriple.defaultPortForProtocol(this.scheme) == this.port);
		boolean portMatches = this.port == Constants.EMPTY_PORT ?
				originUsesDefaultPort :
				(origin.port == Constants.EMPTY_PORT ? thisUsesDefaultPort : this.port == origin.port);
		return schemeMatches && hostMatches && portMatches;
	}

	@Nonnull
	@Override
	public String show() {
		boolean isDefaultPort =
				this.port == Constants.EMPTY_PORT || this.scheme != null && this.port == SchemeHostPortTriple
						.defaultPortForProtocol(this.scheme);
		return (this.scheme == null ? "" : this.scheme + "://") +
				this.host +
				(isDefaultPort ? "" : ":" + (this.port == Constants.WILDCARD_PORT ? "*" : this.port)) +
				(this.path == null ? "" : this.path);
	}

	public static boolean pathMatches(@Nullable String pathA, @Nullable String pathB) {

		if (pathA == null || pathA.isEmpty()) {
			return true;
		}

		if (pathB == null || pathB.isEmpty()) {
			return false;
		}

		if (pathA.matches("/") && pathB.isEmpty()) {
			return true;
		}

		boolean exactMatch = pathA.endsWith("/") ? false : true;

		List<String> pathListA = splitBySpec(pathA, '/');
		List<String> pathListB = splitBySpec(pathB, '/');

		if (pathListA.size() > pathListB.size()) {
			return false;
		}

		if (exactMatch && pathListA.size() != pathListB.size()) {
			return false;
		}

		if (!exactMatch) {
			pathListA.remove(pathListA.size() - 1);
		}

		Iterator it1 = pathListA.iterator();
		Iterator it2 = pathListB.iterator();

		while (it1.hasNext()) {
			String a = decodeString((String) it1.next());
			String b = decodeString((String) it2.next());
			if (!a.equals(b)) {
				return false;
			}
		}
		return true;
	}

	public static String decodeString(@Nonnull String s) {
		try {
			return URLDecoder.decode(s, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			return s;
		}
	}

	public static List<String> splitBySpec(@Nonnull String s, char delim) {
		int off = 0;
		int next;
		ArrayList<String> list = new ArrayList<>();
		while ((next = s.indexOf(delim, off)) != -1) {
			list.add(s.substring(off, next));
			off = next + 1;
		}

		list.add(s.substring(off, s.length()));
		return list;
	}
}
