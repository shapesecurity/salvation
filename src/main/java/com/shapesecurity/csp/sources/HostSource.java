package com.shapesecurity.csp.sources;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Objects;

public class HostSource implements SourceExpression, AncestorSource {
    @Nullable
    private final String scheme;
    @Nonnull
    private final String host;
    @Nullable
    private final String port;
    @Nullable
    private final String path;

    public HostSource(@Nullable String scheme, @Nonnull String host, @Nullable String port, @Nullable String path) {
        this.scheme = scheme;
        this.host = host;
        this.port = port;
        this.path = path;
    }

    @Override
    public boolean equals(@Nullable Object other) {
        if (other == null || !(other instanceof HostSource)) return false;
        HostSource otherPrime = (HostSource) other;
        return Objects.equals(this.scheme, otherPrime.scheme) &&
            Objects.equals(this.host, otherPrime.host) &&
            Objects.equals(this.port, otherPrime.port) &&
            Objects.equals(this.path, otherPrime.path);
    }

    @Override
    public int hashCode() {
        int h = 0;
        if (this.scheme != null) h ^= this.scheme.hashCode() ^ 0xA303EFA3;
        h ^= this.host.hashCode() ^ 0xFB2290B2;
        if (this.port != null) h ^= this.port.hashCode() ^ 0xB54E99F3;
        if (this.path != null) h ^= this.path.hashCode() ^ 0x13324C0E;
        return h;
    }

    @Override
    public boolean matchesUrl(@Nonnull String origin, @Nonnull String url) {
        return true;
    }

    @Nonnull
    @Override
    public String show() {
        return (this.scheme == null ? "" : this.scheme + "://") +
            this.host +
            (this.port == null ? "" : ":" + this.port) +
            (this.path == null ? "" : this.path);
    }
}