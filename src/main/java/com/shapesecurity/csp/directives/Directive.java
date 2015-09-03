package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.None;
import com.shapesecurity.csp.interfaces.Show;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public abstract class Directive<Value extends DirectiveValue> implements Show {
    @Nonnull
    private final String name;

    @Nonnull
    private Set<Value> values;

    Directive(@Nonnull String name, @Nonnull Set<Value> values) {
        this.name = name;
        this.values = values;
    }

    @Nonnull
    public final Stream<Value> values() {
        return values.stream();
    }

    @Nonnull
    protected abstract Directive<Value> construct(Set<Value> newValues);

    @Nonnull
    public Directive<Value> bind(@Nonnull Function<Value, Set<? extends Value>> f) {
        Set<Value> newValues = new LinkedHashSet<>();
        for (Value v : this.values) {
            Set<? extends Value> result = f.apply(v);
            if (result == null) {
                newValues.add(v);
            } else {
                newValues.addAll(result);
            }
        }
        return this.construct(newValues);
    }

    public final void merge(@Nonnull Directive<Value> other) {
        if (other.getClass() != this.getClass()) {
            throw new IllegalArgumentException(this.getClass() + " can be merged with " + this.getClass() +
                    ", but found " + other.getClass());
        }
        this.values = Directive.merge(this.values, other.values);
    }

    boolean equalsHelper(@Nonnull Directive<Value> other) {
        return this.values().count() == other.values().count() &&
                this.values().allMatch((m) -> other.values().anyMatch((n) -> n.equals(m)));
    }

    int hashCodeHelper(int seed) {
        return this.values().map(Object::hashCode).reduce(seed, (a, b) -> a ^ b);
    }

    @Nonnull
    @Override
    public String show() {
        return  Stream.concat(Stream.of(this.name), this.values().map(Show::show)).collect(Collectors.joining(" "));
    }

    @Nonnull
    private static <T> Set<T> merge(@Nonnull Iterable<T> a, @Nonnull Iterable<T> b) {
        Set<T> set = new LinkedHashSet<>();

        if(a.iterator().hasNext() && b.iterator().hasNext() &&
                (a.iterator().next() instanceof None != b.iterator().next() instanceof None)) {
            throw new IllegalArgumentException("'none' can only be merged with another 'none'");
        }

        for (T x : a) {
            set.add(x);
        }
        for (T x : b) {
            set.add(x);
        }
        return set;
    }

    public boolean contains(@Nonnull DirectiveValue value) {
        return values().anyMatch(value::equals);
    }

    @SuppressWarnings("unchecked")
    @Override
    public final boolean equals(@Nullable Object other) {
        return other != null && other.getClass() == this.getClass() && this.equalsHelper((Directive<Value>) other);
    }

    @Override
    public final int hashCode() {
        return this.hashCodeHelper(this.getClass().getCanonicalName().hashCode());
    }
}
