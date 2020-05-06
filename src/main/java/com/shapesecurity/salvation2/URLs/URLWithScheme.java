package com.shapesecurity.salvation2.URLs;


import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Locale;
import java.util.Objects;

public abstract class URLWithScheme {
	@Nonnull
	public final String scheme;
	@Nullable
	public final String host;
	@Nullable
	public final Integer port;
	@Nonnull
	public final String path;


	protected URLWithScheme(@Nonnull String scheme, @Nullable String host, @Nullable Integer port, @Nonnull String path) {
		this.scheme = scheme.toLowerCase(Locale.ENGLISH);
		this.host = host == null ? host : host.toLowerCase(Locale.ENGLISH);
		this.port = port;
		this.path = path;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof URLWithScheme)) return false;
		URLWithScheme that = (URLWithScheme) o;
		return scheme.equals(that.scheme) &&
				Objects.equals(host, that.host) &&
				Objects.equals(port, that.port) &&
				path.equals(that.path);
	}

	@Override
	public int hashCode() {
		return Objects.hash(scheme, host, port, path);
	}
}
