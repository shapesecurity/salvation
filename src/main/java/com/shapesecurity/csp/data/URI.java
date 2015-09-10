package com.shapesecurity.csp.data;

import com.shapesecurity.csp.Constants;
import com.shapesecurity.csp.directives.DirectiveValue;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.regex.Matcher;

public class URI extends Origin implements DirectiveValue {
    @Nullable public final String path;


    public URI(@Nonnull String scheme, @Nonnull String host, @Nonnull int port,
        @Nonnull String path) {
        super(scheme, host, port);
        this.path = path;
    }

    public URI(@Nonnull Origin origin) {
        super(origin.scheme, origin.host, origin.port);
        this.path = null;
    }

    @Nonnull public static URI parse(@Nonnull String uri) throws IllegalArgumentException {
        Matcher matcher = Constants.hostSourcePattern.matcher(uri);
        if (!matcher.find()) {
            throw new IllegalArgumentException("Invalid URI: " + uri);
        }
        String scheme = matcher.group("scheme");
        if (scheme == null) {
            throw new IllegalArgumentException("Invalid URI (missing scheme): " + uri);
        }
        scheme = scheme.substring(0, scheme.length() - 3);
        String portString = matcher.group("port");
        int port;
        if (portString == null) {
            port = Origin.defaultPortForProtocol(scheme);
        } else {
            port = portString.equals(":*") ?
                Constants.WILDCARD_PORT :
                Integer.parseInt(portString.substring(1));
        }
        String host = matcher.group("host");
        String path = matcher.group("path");
        if (path == null) {
            path = "";
        }
        return new URI(scheme, host, port, path);
    }

    @Nonnull public static URI parseWithOrigin(@Nonnull Origin origin, @Nonnull String uri) {
        Matcher matcher = Constants.relativeReportUriPattern.matcher(uri);
        if (!matcher.find()) {
            return URI.parse(uri);
        }
        return new URI(origin.scheme, origin.host, origin.port, matcher.group("path"));
    }

    @Override public boolean equals(Object other) {
        if (!(other instanceof URI))
            return false;
        URI otherUri = (URI) other;
        return super.equals(other) && this.path.equals(otherUri.path);
    }

    @Override public int hashCode() {
        int h = super.hashCode();
        h ^= this.path.hashCode() ^ 0x3F8C5C1C;
        return h;
    }

    @Nonnull @Override public String show() {
        return super.show() + this.path;
    }
}
