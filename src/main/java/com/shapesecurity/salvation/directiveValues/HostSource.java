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

    public HostSource(@Nullable String scheme, @Nonnull String host, int port, @Nullable String path) {
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

        // safe to do uniform comparison of scheme and host
        return Objects.equals(this.scheme != null ? this.scheme.toLowerCase() : null ,
                otherPrime.scheme != null ? otherPrime.scheme.toLowerCase() : null) &&
            Objects.equals(this.host != null ? this.host.toLowerCase() : null,
                otherPrime.host != null ? otherPrime.host.toLowerCase() : null) &&
            this.port == otherPrime.port &&
            Objects.equals(this.path, otherPrime.path);
    }

    @Override public int hashCode() {

        // scheme and host matching is case-insensitive
        int h = 0;
        if (this.scheme != null)
            h ^= this.scheme.toLowerCase().hashCode() ^ 0xA303EFA3;
        h ^= this.host.toLowerCase().hashCode() ^ 0xFB2290B2;
        h ^= this.port ^ 0xB54E99F3;
        if (this.path != null)
            h ^= this.path.hashCode() ^ 0x13324C0E;
        return h;
    }

    public boolean isWildcard() {
        return this.host.equals("*") && this.scheme == null && this.port == Constants.EMPTY_PORT && this.path == null;
    }

    @Override public boolean matchesSource(@Nonnull Origin origin, @Nonnull URI resource) {
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
        boolean hostMatches = this.host.equals("*") || (this.host.startsWith("*.") ?
            resource.host.toLowerCase().endsWith(this.host.substring(1).toLowerCase()) :
            this.host.equalsIgnoreCase(resource.host));
        boolean uriUsesDefaultPort = resource.port == Constants.EMPTY_PORT
            || SchemeHostPortTriple.defaultPortForProtocol(resource.scheme) == resource.port;
        boolean thisUsesDefaultPort = this.scheme != null && (this.port == Constants.EMPTY_PORT
            || SchemeHostPortTriple.defaultPortForProtocol(this.scheme) == this.port);
        boolean portMatches = this.port == Constants.WILDCARD_PORT || (thisUsesDefaultPort && uriUsesDefaultPort) ||
                (this.port == Constants.EMPTY_PORT ?
            uriUsesDefaultPort :
            (resource.port == Constants.EMPTY_PORT ? thisUsesDefaultPort : this.port == resource.port));
        boolean pathMatches = this.path == null || (this.path.endsWith("/") ?
            resource.path.startsWith(this.path) :
            this.path.equals(resource.path));
        return schemeMatches && hostMatches && portMatches && pathMatches;
    }

    @Override public boolean matchesSource(@Nonnull Origin origin, @Nonnull GUID resource) {
        String originScheme = null;
        if (origin instanceof GUID) {
            originScheme = ((GUID)origin).scheme();
        }
        String resourceScheme = resource.scheme();
        if (origin instanceof GUID && originScheme != null && resourceScheme != null) {
            return originScheme.equalsIgnoreCase(resourceScheme);
        } else {
            return false;
        }
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
        boolean isDefaultPort =
            this.port == Constants.EMPTY_PORT || this.scheme != null && this.port == SchemeHostPortTriple
                .defaultPortForProtocol(this.scheme);
        return (this.scheme == null ? "" : this.scheme + "://") +
            this.host +
            (isDefaultPort ? "" : ":" + (this.port == Constants.WILDCARD_PORT ? "*" : this.port)) +
            (this.path == null ? "" : this.path);
    }
}
