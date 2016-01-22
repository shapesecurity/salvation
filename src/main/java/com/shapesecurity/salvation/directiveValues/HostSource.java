package com.shapesecurity.salvation.directiveValues;

import com.shapesecurity.salvation.Constants;
import com.shapesecurity.salvation.data.GUID;
import com.shapesecurity.salvation.data.Origin;
import com.shapesecurity.salvation.data.SchemeHostPortTriple;
import com.shapesecurity.salvation.data.URI;
import com.shapesecurity.salvation.interfaces.MatchesSource;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Objects;

public class HostSource implements SourceExpression, AncestorSource, MatchesSource {
    public static final HostSource WILDCARD = new HostSource(null, "*", Constants.EMPTY_PORT, null);
    private static final int WILDCARD_HASHCODE = 0x9F4E3EEA;
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
        return this.host.equals("*") && this.scheme == null && this.port == Constants.EMPTY_PORT
            && this.path == null;
    }

    @Override public boolean matchesSource(@Nonnull Origin origin, @Nonnull URI source) {
        if (!(origin instanceof SchemeHostPortTriple)) {
            return false;
        }
        SchemeHostPortTriple shpOrigin = (SchemeHostPortTriple) origin;
        if (this.isWildcard()) {
            return true;
        }
        boolean schemeMatches;
        if (this.scheme == null) {
            schemeMatches = source.scheme.equalsIgnoreCase("http") ?
                shpOrigin.scheme.equalsIgnoreCase("http") || shpOrigin.scheme
                    .equalsIgnoreCase("https") :
                source.scheme.equalsIgnoreCase(shpOrigin.scheme);
        } else {
            schemeMatches = this.scheme.equalsIgnoreCase(source.scheme);
        }
        boolean hostMatches = this.host.equals("*") || (this.host.startsWith("*.") ?
            source.host.endsWith(this.host.substring(1)) :
            this.host.equalsIgnoreCase(source.host));
        boolean uriUsesDefaultPort = source.port == Constants.EMPTY_PORT
            || SchemeHostPortTriple.defaultPortForProtocol(source.scheme) == source.port;
        boolean thisUsesDefaultPort = this.scheme != null && (this.port == Constants.EMPTY_PORT
            || SchemeHostPortTriple.defaultPortForProtocol(this.scheme) == this.port);
        boolean portMatches =
            this.port == Constants.WILDCARD_PORT || (this.port == Constants.EMPTY_PORT ?
                uriUsesDefaultPort :
                (source.port == Constants.EMPTY_PORT ?
                    thisUsesDefaultPort :
                    this.port == source.port));
        boolean pathMatches = this.path == null || (this.path.endsWith("/") ?
            source.path.toLowerCase().startsWith(this.path.toLowerCase()) :
            this.path.equalsIgnoreCase(source.path));
        return schemeMatches && hostMatches && portMatches && pathMatches;
    }

    @Override public boolean matchesSource(@Nonnull Origin origin, @Nonnull GUID source) {
        return false;
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

    @Nonnull @Override public String show() {
        boolean isDefaultPort = this.port == Constants.EMPTY_PORT
            || this.scheme != null && this.port == SchemeHostPortTriple
            .defaultPortForProtocol(this.scheme);
        return (this.scheme == null ? "" : this.scheme + "://") +
            this.host +
            (isDefaultPort ? "" : ":" + (this.port == Constants.WILDCARD_PORT ? "*" : this.port)) +
            (this.path == null ? "" : this.path);
    }
}
