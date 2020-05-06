package com.shapesecurity.salvation2.URLs;

import com.shapesecurity.salvation2.Constants;

import javax.annotation.Nonnull;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;

public class URI extends URLWithScheme {

	public URI(@Nonnull String scheme, @Nonnull String host, int port, @Nonnull String path) {
		super(scheme, host, port, path);
	}

	@Nonnull
	public static Optional<URI> parseURI(@Nonnull String uri) {
		Matcher matcher = Constants.hostSourcePattern.matcher(uri);
		if (!matcher.find()) {
			return Optional.empty();
		}
		String scheme = matcher.group("scheme");
		if (scheme == null) {
			return Optional.empty();
		}
		scheme = scheme.substring(0, scheme.length() - 3);
		String portString = matcher.group("port");
		int port;
		if (portString == null) {
			port = URI.defaultPortForProtocol(scheme.toLowerCase(Locale.ENGLISH));
		} else {
			port = portString.equals(":*") ? Constants.WILDCARD_PORT : Integer.parseInt(portString.substring(1));
		}
		String host = matcher.group("host");
		String path = matcher.group("path");
		if (path == null) {
			path = "";
		}
		return Optional.of(new URI(scheme, host, port, path));
	}

	// http://www.w3.org/TR/url/#default-port
	public static int defaultPortForProtocol(@Nonnull String scheme) {
		// NB this should just only be called with lowercase'd schemes
		switch (scheme) {
			case "ftp":
				return 21;
			case "file":
				return Constants.EMPTY_PORT;
			case "gopher":
				return 70;
			case "http":
				return 80;
			case "https":
				return 443;
			case "ws":
				return 80;
			case "wss":
				return 443;
			default:
				return Constants.EMPTY_PORT;
		}
	}
}
