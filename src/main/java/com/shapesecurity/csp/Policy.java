package com.shapesecurity.csp;

import com.shapesecurity.csp.directives.Directive;
import com.shapesecurity.csp.directives.DirectiveValue;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

public class Policy implements Show {

    @Nonnull
    private final Map<Class<?>, Directive<? extends DirectiveValue>> directives;

    public Policy() {
        this.directives = new LinkedHashMap<>();
    }

    public void merge(@Nonnull Policy other) {
        other.getDirectives().forEach(this::mergeDirective);
    }

    // merge a directive if it does not exist; used for policy manipulation and composition
    @SuppressWarnings("unchecked")
    private <V extends DirectiveValue, T extends Directive<V>> void mergeDirective(@Nonnull T directive) {
        T oldDirective = (T) this.directives.get(directive.getClass());
        if (oldDirective != null) {
            oldDirective.merge(directive);
        } else {
            this.directives.put(directive.getClass(), directive);
        }
    }

    // only add a directive if it doesn't exist; used for handling duplicate directives in CSP headers
    public <V extends DirectiveValue, T extends Directive<V>> void addDirective(@Nonnull T d) {
        Directive<? extends DirectiveValue> directive = this.directives.get(d.getClass());
        if (directive == null) {
            this.directives.put(d.getClass(), d);
        }
    }

    @Nonnull
    public Collection<Directive<? extends DirectiveValue>> getDirectives() {
        return this.directives.values();
    }

    @SuppressWarnings("unchecked")
    @Nullable
    public <V extends DirectiveValue, T extends Directive<V>> T getDirectiveByType(@Nonnull Class<T> type) {
        T d = (T) this.directives.get(type);
        if (d == null) return null;
        return d;
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
        for (Directive<?> d : this.directives.values()) {
            if (!first) sb.append("; ");
            first = false;
            sb.append(d.show());
        }
        return sb.toString();
    }
}
