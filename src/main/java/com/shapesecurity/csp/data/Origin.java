package com.shapesecurity.csp.data;

import com.shapesecurity.csp.interfaces.Show;

import javax.annotation.Nonnull;
import java.util.Objects;

public class Origin implements Show {
    @Nonnull
    public final String scheme;
    @Nonnull
    public final String host;
    @Nonnull
    public final String port;

    protected Origin(@Nonnull String scheme, @Nonnull String host, @Nonnull String port) {
        this.scheme = scheme.toLowerCase();
        this.host = host.toLowerCase();
        this.port = port;
    }

    // TODO: make ports integers everywhere
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

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof URI)) return false;
        Origin otherOrigin = (Origin) other;
        return Objects.equals(this.scheme, otherOrigin.scheme) && this.host.equals(otherOrigin.host) && this.port.equals(otherOrigin.port);
    }

    @Override
    public int hashCode() {
        int h = 0;
        h ^= this.scheme.hashCode() ^ 0x6468FB51;
        h ^= this.host.hashCode() ^ 0x8936B847;
        h ^= this.port.hashCode() ^ 0x1AA66413;
        return h;
    }

    @Nonnull
    @Override
    public String show() {
        boolean isDefaultPort = this.port.isEmpty() || defaultPortForProtocol(this.scheme).equals(this.port);
        return this.scheme + "://" +
            this.host +
            (isDefaultPort ? "" : ":" + this.port);
    }
}
