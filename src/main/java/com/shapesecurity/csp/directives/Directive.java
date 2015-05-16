package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.Show;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public abstract class Directive implements Show {
    @Nonnull
    public final String name;

    Directive(@Nonnull String name) {
        this.name = name;
    }

    @Nonnull
    abstract Stream<? extends DirectiveValue> values();

    public abstract void merge(@Nonnull Directive other);

    public boolean equalsHelper(@Nonnull Directive other) {
        return this.values().count() == other.values().count() &&
            this.values().allMatch((m) -> other.values().anyMatch((n) -> n.equals(m)));
    }

    public int hashCodeHelper(int seed) {
        return this.values().map(Object::hashCode).reduce(seed, (a, b) -> a ^ b);
    }

    @Nonnull
    @Override
    public String show() {
        return this.values().map(Show::show).reduce(this.name, (a, b) -> a + " " + b);
    }

    @Nonnull
    static <T> Stream<T> merge(@Nonnull Stream<T> a, @Nonnull Stream<T> b) {
        return Stream.concat(a, b.filter((x) -> a.anyMatch(x::equals)));
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
}
