package com.shapesecurity.salvation.directiveValues;


import com.shapesecurity.salvation.data.GUID;
import com.shapesecurity.salvation.data.Origin;
import com.shapesecurity.salvation.data.SchemeHostPortTriple;
import com.shapesecurity.salvation.data.URI;
import com.shapesecurity.salvation.interfaces.MatchesSource;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class SchemeSource implements SourceExpression, AncestorSource, MatchesSource {
    @Nonnull private final String value;

    public SchemeSource(@Nonnull String value) {
        this.value = value;
    }

    @Override public boolean matchesSource(@Nonnull Origin origin, @Nonnull URI resource) {
        SchemeHostPortTriple shpOrigin = (SchemeHostPortTriple) origin;
        return this.value.matches(resource.scheme);
    }

    @Override public boolean matchesSource(@Nonnull Origin origin, @Nonnull GUID resource) {
        SchemeHostPortTriple shpOrigin = (SchemeHostPortTriple) origin;
        String resourceString = resource.value.toLowerCase();
        return resourceString.startsWith(this.value.toLowerCase() + ":") ||
                resourceString.startsWith(shpOrigin.scheme + ":");
    }

    // Note: WebSocket schemes are not networks schemes but CSP spec decided to treat them as equivalent to http/https
    public boolean matchesNetworkScheme() {
        return this.value.equalsIgnoreCase("ftp") || this.value.equalsIgnoreCase("http") ||
            this.value.equalsIgnoreCase("https") || this.value.equalsIgnoreCase("ws") ||
            this.value.equalsIgnoreCase("wss");
    }

    @Override public boolean equals(@Nullable Object other) {
        if (other == null || !(other instanceof SchemeSource))
            return false;
        return this.value.equals(((SchemeSource) other).value);
    }

    @Override public int hashCode() {
        return this.value.hashCode();
    }

    @Nonnull @Override public String show() {
        return this.value + ":";
    }
}
