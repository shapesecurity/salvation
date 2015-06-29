package com.shapesecurity.csp;

import com.shapesecurity.csp.directives.DirectiveValue;

import javax.annotation.Nonnull;
import java.util.Objects;
import java.util.regex.Matcher;

public class URI extends Origin implements DirectiveValue {
    @Nonnull
    public final String path;


    @Nonnull
    public static URI parse(@Nonnull String uri) throws IllegalArgumentException {
        Matcher matcher = Utils.hostSourcePattern.matcher(uri);
        if (!matcher.find()) {
            throw new IllegalArgumentException("Invalid URI: " + uri);
        }
        String scheme = matcher.group("scheme");
        if (scheme == null) {
            throw new IllegalArgumentException("Invalid URI (missing scheme): " + uri);
        }
        scheme = scheme.substring(0, scheme.length() - 3);
        String port = matcher.group("port");
        port = port == null ? defaultPortForProtocol(scheme) : port.substring(1, port.length());
        String host = matcher.group("host");
        String path = matcher.group("path");
        if (path == null) {
            path = "";
        }
        return new URI(scheme, host, port, path);
    }

    @Nonnull
    public static URI parseWithOrigin(@Nonnull Origin origin, @Nonnull String uri) {
        Matcher matcher = Utils.relativeReportUriPattern.matcher(uri);
        if (!matcher.find()) {
            return URI.parse(uri);
        }
        return new URI(origin.scheme, origin.host, origin.port, matcher.group("path"));
    }

    public URI(@Nonnull String scheme, @Nonnull String host, @Nonnull String port, @Nonnull String path) {
        super(scheme, host, port);
        this.path = path;
    }

    public boolean sameOrigin(@Nonnull URI other) {
        return Objects.equals(this.scheme, other.scheme) && this.host.equals(other.host) && this.port.equals(other.port);
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof URI)) return false;
        URI otherUri = (URI) other;
        return super.equals(other) && this.path.equals(otherUri.path);
    }

    @Override
    public int hashCode() {
        int h = super.hashCode();
        h ^= this.path.hashCode() ^ 0x3F8C5C1C;
        return h;
    }

    @Nonnull
    @Override
    public String show() {
        return super.show() + this.path;
    }
}
