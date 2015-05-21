package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.Show;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public abstract class Directive<Value extends DirectiveValue> implements Show {
    @Nonnull
    private final String name;

    @Nonnull
    // @Nonempty
    protected List<Value> values;

    protected Directive(@Nonnull String name, @Nonnull List<Value> values) {
        this.name = name;
        this.values = values;
    }

    @Nonnull
    public final Stream<Value> values() {
        return values.stream();
    }

    public final void merge(@Nonnull Directive<Value> other) {
        if (other.getClass() != this.getClass()) {
            throw new IllegalArgumentException(other.getClass() + " can be merged with " + other.getClass() +
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
    public String show()  {
        return  Stream.concat(Stream.of(this.name), this.values().map(Show::show)).collect(Collectors.joining(" "));
    }

    @Nonnull
    static <T> List<T> merge(@Nonnull Iterable<T> a, @Nonnull Iterable<T> b) {
        ArrayList<T> list = new ArrayList<>();
        for (T x : a) {
            list.add(x);
        }
        for (T x : b) {
            if (!list.contains(x)) {
                list.add(x);
            }
        }
        return list;
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
