package com.shapesecurity.csp.data;

import com.shapesecurity.csp.Constants;
import com.shapesecurity.csp.directives.DirectiveValue;

import javax.annotation.Nonnull;
import java.util.regex.Matcher;

public class URI extends SchemeHostPortTriple implements DirectiveValue {
    @Nonnull public final String path;


    public URI(@Nonnull String scheme, @Nonnull String host, int port, @Nonnull String path) {
        super(scheme, host, port);
        this.path = path;
    }

    public URI(@Nonnull SchemeHostPortTriple origin) {
        super(origin.scheme, origin.host, origin.port);
        this.path = "";
    }

    @Nonnull public static URI parse(@Nonnull String uri) throws IllegalArgumentException {
        Matcher matcher = Constants.hostSourcePattern.matcher(uri);
        if (!matcher.find()) {
            throw new IllegalArgumentException("Invalid URI");
        }
        String scheme = matcher.group("scheme");
        if (scheme == null) {
            throw new IllegalArgumentException("Invalid URI (missing scheme)");
        }
        scheme = scheme.substring(0, scheme.length() - 3);
        String portString = matcher.group("port");
        int port;
        if (portString == null) {
            port = SchemeHostPortTriple.defaultPortForProtocol(scheme);
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
        if (!(origin instanceof SchemeHostPortTriple)) {
            throw new IllegalArgumentException("Cannot use relative URI with GUID origin");
        }
        SchemeHostPortTriple shpOrigin = (SchemeHostPortTriple) origin;
        return new URI(shpOrigin.scheme, shpOrigin.host, shpOrigin.port, matcher.group("path"));
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
