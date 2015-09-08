package com.shapesecurity.csp.data;

import com.shapesecurity.csp.Constants;
import com.shapesecurity.csp.interfaces.Show;

import javax.annotation.Nonnull;
import java.util.Objects;

public class Origin implements Show {
    @Nonnull
    public final String scheme;
    @Nonnull
    public final String host;
    @Nonnull
    public final int port;

    protected Origin(@Nonnull String scheme, @Nonnull String host, @Nonnull int port) {
        this.scheme = scheme.toLowerCase();
        this.host = host.toLowerCase();
        this.port = port;
    }


    // http://www.w3.org/TR/url/#default-port
    @Nonnull
    public static int defaultPortForProtocol(@Nonnull String scheme) {
        switch (scheme.toLowerCase()) {
            case "ftp": return 21;
            case "file": return Constants.EMPTY_PORT;
            case "gopher": return 70;
            case "http": return 80;
            case "https": return 443;
            case "ws": return 80;
            case "wss": return 443;
            default: return Constants.EMPTY_PORT;
        }
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof URI)) return false;
        Origin otherOrigin = (Origin) other;
        return Objects.equals(this.scheme, otherOrigin.scheme) && this.host.equals(otherOrigin.host) && this.port == otherOrigin.port;
    }

    @Override
    public int hashCode() {
        int h = 0;
        h ^= this.scheme.hashCode() ^ 0x6468FB51;
        h ^= this.host.hashCode() ^ 0x8936B847;
        h ^= this.port ^ 0x1AA66413;
        return h;
    }

    @Nonnull
    @Override
    public String show() {
        boolean isDefaultPort = this.port == Constants.EMPTY_PORT || defaultPortForProtocol(this.scheme) == this.port;
        return this.scheme + "://" +
            this.host +
            (isDefaultPort ? "" : ":" + this.port);
    }
}
