package com.shapesecurity.salvation2.Values;

import com.shapesecurity.salvation2.Constants;
import com.shapesecurity.salvation2.URLs.URI;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;

public class Host {
	@Nullable
	public final String scheme;
	@Nonnull
	public final String host;
	public final int port;
	@Nullable
	public final String path;

	public static final Host STAR = new Host(null, "*", Constants.EMPTY_PORT, null);

	private Host(String scheme, String host, int port, String path) {
		this.scheme = scheme;
		this.host = host;
		this.port = port;
		this.path = path;
	}

	public static Optional<Host> parseHost(String value) {
		Matcher matcher = Constants.hostSourcePattern.matcher(value);
		if (matcher.find()) {
			String scheme = matcher.group(1);
			if (scheme != null) {
				scheme = scheme.substring(0, scheme.length() - 3).toLowerCase(Locale.ENGLISH);
			}
			String portString = matcher.group(3);
			int port;
			if (portString == null) {
				port = Constants.EMPTY_PORT;
			} else {
				port = portString.equals(":*") ? Constants.WILDCARD_PORT : Integer.parseInt(portString.substring(1));
			}
			// Hosts are only consumed lowercase: https://w3c.github.io/webappsec-csp/#host-part-match
			String host = matcher.group(2).toLowerCase(Locale.ENGLISH); // There is no possible NPE here; host is not optional
			String path = matcher.group(4);

			// TODO contemplate warning for paths which contain `//`, `/../`, or `/./`, since those will never match an actual request
			// TODO contemplate warning for ports which are implied by their scheme
			// TODO think about IDN and percent-encoding :((((
			// We really want paths to be minimally percent-encoded - all and only the things which need to be
			// (IDN isn't that bad because we restrict to ascii)
			return Optional.of(new Host(scheme, host, port, path));
		} else {
			return Optional.empty();
		}
	}

	@Override
	public String toString() {
		boolean isDefaultPort =
				this.port == Constants.EMPTY_PORT || this.scheme != null && this.port == URI
						.defaultPortForProtocol(this.scheme);
		return (this.scheme == null ? "" : this.scheme + "://") +
				this.host +
				(isDefaultPort ? "" : ":" + (this.port == Constants.WILDCARD_PORT ? "*" : this.port)) +
				(this.path == null ? "" : this.path);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		Host that = (Host) o;
		return port == that.port &&
				Objects.equals(scheme, that.scheme) &&
				Objects.equals(host, that.host) &&
				Objects.equals(path, that.path);
	}

	@Override
	public int hashCode() {
		return Objects.hash(scheme, host, port, path);
	}
}
