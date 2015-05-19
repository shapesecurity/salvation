package com.shapesecurity.csp;

import com.shapesecurity.csp.directives.Directive;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

public class Policy implements Show {

    @Nonnull
    private final Map<Class<? extends Directive>, Directive> directives;

    public Policy() {
        this.directives = new LinkedHashMap<>();
    }

    public void merge(@Nonnull Policy other) {
        other.getDirectives().forEach(this::mergeDirective);
    }

    // merge a directive if it does not exist; used for policy manipulation and composition
    private void mergeDirective(@Nonnull Directive d) {
        if (!this.directives.containsKey(d.getClass())) {
            this.directives.get(d.getClass()).merge(d);
        } else {
            this.directives.put(d.getClass(), d);
        }
    }

    // only add a directive if it doesn't exist; used for handling duplicate directives in CSP headers
    public void addDirective(@Nonnull Directive d) {
        if (!this.directives.containsKey(d.getClass())) {
            this.directives.put(d.getClass(), d);
        }
    }

    @Nonnull
    public Collection<Directive> getDirectives() {
        return this.directives.values();
    }

    @Nullable
    public <T extends Directive> T getDirectiveByType(@Nonnull Class<T> type) {
        Directive d = this.directives.get(type);
        if (d == null) return null;
        return (T) d;
    }

    @Override
    public boolean equals(@Nullable Object other) {
        if (other == null || !(other instanceof Policy)) return false;
        return this.directives.size() == ((Policy) other).directives.size() &&
            this.directives.equals(((Policy) other).directives);
    }

    @Override
    public int hashCode() {
        return this.directives.values().stream().map(Object::hashCode).reduce(0x19E465E0, (a, b) -> a ^ b);
    }

    @Nonnull
    @Override
    public String show() {
        StringBuilder sb = new StringBuilder();
        if (this.directives.isEmpty()) {
            return "";
        }
        boolean first = true;
        for (Directive d : this.directives.values()) {
            if (!first) sb.append(" ;");
            first = false;
            sb.append(d.show());
        }
        return sb.toString();
    }
}
