package com.shapesecurity.csp;

import com.shapesecurity.csp.directives.DirectiveValue;

import javax.annotation.Nonnull;
import java.util.Objects;
import java.util.regex.Matcher;

public class URI implements DirectiveValue {
    @Nonnull
    public final String scheme;
    @Nonnull
    public final String host;
    @Nonnull
    public final String port;
    @Nonnull
    public final String path;


    @Nonnull
    public static String defaultPortForProtocol(@Nonnull String scheme) {
        switch (scheme.toLowerCase()) {
            case "ftp": return "21";
            case "file": return "";
            case "gopher": return "70";
            case "http": return "80";
            case "https": return "443";
            case "ws": return "80";
            case "wss": return "443";
            default: return "";
        }
    }

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
    public static URI parseWithOrigin(@Nonnull URI origin, @Nonnull String uri) {
        Matcher matcher = Utils.relativeReportUriPattern.matcher(uri);
        if (!matcher.find()) {
            return URI.parse(uri);
        }
        return new URI(origin.scheme, origin.host, origin.port, matcher.group("path"));
    }

    public URI(@Nonnull String scheme, @Nonnull String host, @Nonnull String port, @Nonnull String path) {
        this.scheme = scheme.toLowerCase();
        this.host = host.toLowerCase();
        this.port = port;
        this.path = path;
    }

    public boolean sameOrigin(@Nonnull URI other) {
        return Objects.equals(this.scheme, other.scheme) && this.host.equals(other.host) && this.port.equals(other.port);
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof URI)) return false;
        URI otherUri = (URI) other;
        return this.sameOrigin(otherUri) && this.path.equals(otherUri.path);
    }

    @Override
    public int hashCode() {
        int h = 0;
        h ^= this.scheme.hashCode() ^ 0x6468FB51;
        h ^= this.host.hashCode() ^ 0x8936B847;
        h ^= this.port.hashCode() ^ 0x1AA66413;
        h ^= this.path.hashCode() ^ 0x3F8C5C1C;
        return h;
    }

    @Nonnull
    @Override
    public String show() {
        return this.showOrigin() + this.path;
    }

    @Nonnull
    public String showOrigin() {
        return this.scheme + "://" +
                this.host +
                (this.port.isEmpty() || defaultPortForProtocol(this.scheme).equals(this.port) ? "" : ":" + this.port);
    }
}
