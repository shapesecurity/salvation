package com.shapesecurity.csp.directiveValues;

import com.shapesecurity.csp.Constants;
import com.shapesecurity.csp.data.Origin;
import com.shapesecurity.csp.data.URI;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Objects;

public class HostSource implements SourceExpression, AncestorSource {
    @Nullable private final String scheme;
    @Nonnull private final String host;
    private final int port;
    @Nullable private final String path;

    public HostSource(@Nullable String scheme, @Nonnull String host, int port,
        @Nullable String path) {
        this.scheme = scheme;
        this.host = host;
        this.port = port;
        this.path = path;
    }

    private static final int WILDCARD_HASHCODE = 0x9F4E3EEA;
    public static final HostSource WILDCARD = new HostSource(null, "*", Constants.EMPTY_PORT, null);

    @Override public boolean equals(@Nullable Object other) {
        if (other == null || !(other instanceof HostSource))
            return false;
        HostSource otherPrime = (HostSource) other;
        if (this.isWildcard() && otherPrime.isWildcard())
            return true;
        return Objects.equals(this.scheme, otherPrime.scheme) &&
            Objects.equals(this.host, otherPrime.host) &&
            this.port == otherPrime.port &&
            Objects.equals(this.path, otherPrime.path);
    }

    @Override public int hashCode() {
        if (this.isWildcard()) {
            return WILDCARD_HASHCODE;
        }
        int h = 0;
        if (this.scheme != null)
            h ^= this.scheme.hashCode() ^ 0xA303EFA3;
        h ^= this.host.hashCode() ^ 0xFB2290B2;
        h ^= this.port ^ 0xB54E99F3;
        if (this.path != null)
            h ^= this.path.hashCode() ^ 0x13324C0E;
        return h;
    }

    public boolean isWildcard() {
        return this.host.equals("*") && this.scheme == null && this.port == Constants.EMPTY_PORT;
    }

    @Override public boolean matchesUri(@Nonnull Origin origin, @Nonnull URI uri) {
        if (this.isWildcard()) {
            return !uri.scheme.equals("blob") && !uri.scheme.equals("data") && !uri.scheme.equals("filesystem");
        }
        boolean schemeMatches;
        if (this.scheme == null) {
            schemeMatches =
                origin.scheme.equalsIgnoreCase("http")
                    ? uri.scheme.equalsIgnoreCase("http") || uri.scheme.equalsIgnoreCase("https")
                    : uri.scheme.equalsIgnoreCase(origin.scheme);
        } else {
            schemeMatches = this.scheme.equalsIgnoreCase(uri.scheme);
        }
        boolean hostMatches = this.host.equals("*") ||
            (this.host.startsWith("*.")
                ? uri.host.endsWith(this.host.substring(1))
                : this.host.equalsIgnoreCase(uri.host));
        boolean uriUsesDefaultPort = uri.port == Constants.EMPTY_PORT
            || Origin.defaultPortForProtocol(uri.scheme) == uri.port;
        boolean thisUsesDefaultPort = this.scheme != null && (this.port == Constants.EMPTY_PORT
            || Origin.defaultPortForProtocol(this.scheme) == this.port);
        boolean portMatches =
            this.port == Constants.WILDCARD_PORT || (this.port == Constants.EMPTY_PORT ?
                uriUsesDefaultPort :
                (uri.port == Constants.EMPTY_PORT ? thisUsesDefaultPort : this.port == uri.port));
        boolean pathMatches = this.path == null || (this.path.endsWith("/") ?
            uri.path.toLowerCase().startsWith(this.path.toLowerCase()) :
            this.path.equalsIgnoreCase(uri.path));
        return schemeMatches && hostMatches && portMatches && pathMatches;
    }

    public boolean matchesOnlyOrigin(@Nonnull Origin origin) {
        boolean schemeMatches = this.scheme != null && this.scheme.equalsIgnoreCase(origin.scheme);
        boolean hostMatches = this.host.equalsIgnoreCase(origin.host);
        boolean originUsesDefaultPort = origin.port == Constants.EMPTY_PORT
            || Origin.defaultPortForProtocol(origin.scheme) == origin.port;
        boolean thisUsesDefaultPort = this.scheme != null && (this.port == Constants.EMPTY_PORT
            || Origin.defaultPortForProtocol(this.scheme) == this.port);
        boolean portMatches = this.port == Constants.EMPTY_PORT ?
            originUsesDefaultPort :
            (origin.port == Constants.EMPTY_PORT ? thisUsesDefaultPort : this.port == origin.port);
        return schemeMatches && hostMatches && portMatches;
    }

    @Nonnull @Override public String show() {
        boolean isDefaultPort = this.port == Constants.EMPTY_PORT ||
            this.scheme != null && this.port == Origin.defaultPortForProtocol(this.scheme) ||
            this.scheme == null && this.port == Constants.WILDCARD_PORT;
        return (this.scheme == null ? "" : this.scheme + "://") +
            this.host +
            (isDefaultPort ? "" : ":" + (this.port == Constants.WILDCARD_PORT ? "*" : this.port)) +
            (this.path == null ? "" : this.path);
    }
}
