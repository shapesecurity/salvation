package com.shapesecurity.csp.directiveValues;

import com.shapesecurity.csp.data.Origin;
import com.shapesecurity.csp.data.URI;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Objects;

public class HostSource implements SourceExpression, AncestorSource {
    @Nullable
    private final String scheme;
    @Nonnull
    private final String host;
    @Nonnull
    private final String port;
    @Nullable
    private final String path;

    public HostSource(@Nullable String scheme, @Nonnull String host, @Nonnull String port, @Nullable String path) {
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
        h ^= this.port.hashCode() ^ 0xB54E99F3;
        if (this.path != null) h ^= this.path.hashCode() ^ 0x13324C0E;
        return h;
    }

    @Override
    public boolean matchesUri(@Nonnull Origin origin, @Nonnull URI uri) {
        if (this.scheme == null && this.port.isEmpty() && this.host.equals("*")) return true;
        boolean schemeMatches =
            this.scheme == null
                ? uri.scheme.equalsIgnoreCase("http") || uri.scheme.equalsIgnoreCase("https")
                : this.scheme.equalsIgnoreCase(uri.scheme);
        boolean hostMatches =
            this.host.equals("*") || (this.host.startsWith("*.")
                ? uri.host.endsWith(this.host.substring(2))
                : this.host.equalsIgnoreCase(uri.host));
        boolean portMatches =
            this.port.isEmpty() && (uri.port.isEmpty() || Origin.defaultPortForProtocol(uri.scheme).equals(uri.port)) ||
            this.port.equals("*") ||
                    (!this.port.isEmpty() && !uri.port.isEmpty()) &&
                            (Integer.parseInt(this.port, 10) ==  Integer.parseInt(uri.port, 10));
        boolean pathMatches = this.path == null || this.path.matches(uri.path);
        return  schemeMatches && hostMatches && portMatches && pathMatches;
    }

    @Nonnull
    @Override
    public String show() {
        return (this.scheme == null ? "" : this.scheme + "://") +
            this.host +
            (this.port.isEmpty() ? "" : ":" + this.port) +
            (this.path == null ? "" : this.path);
    }
}