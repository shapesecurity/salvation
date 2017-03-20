package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.HostSource;
import com.shapesecurity.salvation.directiveValues.None;
import com.shapesecurity.salvation.interfaces.Show;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public abstract class Directive<Value extends DirectiveValue> implements Show {
    @Nonnull public final String name;

    @Nonnull private Set<Value> values;

    public static List<Class<? extends Directive>> getFetchDirectives() {
        return fetchDirectives;
    }

    public static List<Class<? extends Directive>> getNestedContextDirectives() {
        return nestedContextDirectives;
    }

    static List<Class<? extends Directive>> fetchDirectives = new ArrayList<>();
    static List<Class<? extends Directive>> nestedContextDirectives = new ArrayList<>();

    static public final int FETCH_DIRECIVE_COUNT;
    static public final int NESTED_CONTEXT_DIRECTIVE_COUNT;

    static void register(Class<? extends Directive> directiveClass) {
        if (NestedContextDirective.class.isAssignableFrom(directiveClass)) {
            nestedContextDirectives.add(directiveClass);
        }
        if (FetchDirective.class.isAssignableFrom(directiveClass) && directiveClass != DefaultSrcDirective.class && directiveClass != FrameSrcDirective.class && directiveClass != WorkerSrcDirective.class) {
            fetchDirectives.add(directiveClass);
        }
    }

    static {
        // NOTE: new directive types must be registered here
        register(ScriptSrcDirective.class);
        register(StyleSrcDirective.class);
        register(ImgSrcDirective.class);
        register(ChildSrcDirective.class);
        register(ConnectSrcDirective.class);
        register(FontSrcDirective.class);
        register(MediaSrcDirective.class);
        register(ObjectSrcDirective.class);
        register(ManifestSrcDirective.class);
        register(DefaultSrcDirective.class);
        register(ReferrerDirective.class);
        register(FrameSrcDirective.class);
        register(ReportUriDirective.class);
        register(ReportToDirective.class);
        register(RequireSriForDirective.class);
        register(FrameAncestorsDirective.class);
        register(SandboxDirective.class);
        register(PluginTypesDirective.class);
        register(FormActionDirective.class);
        register(UpgradeInsecureRequestsDirective.class);
        register(WorkerSrcDirective.class);
        register(BlockAllMixedContentDirective.class);
        register(BaseUriDirective.class);
        FETCH_DIRECIVE_COUNT = fetchDirectives.size();
        NESTED_CONTEXT_DIRECTIVE_COUNT = nestedContextDirectives.size();
    }

    Directive(@Nonnull String name, @Nonnull Set<Value> values) {
        this.name = name;
        this.values = values;
    }

    @Nonnull private static <T> Set<T> union(@Nonnull Set<T> a, @Nonnull Set<T> b) {
        Set<T> set = new LinkedHashSet<>();

        set.addAll(a);
        set.addAll(b);

        Optional<T> star = set.stream().filter(x -> x instanceof HostSource && ((HostSource) x).isWildcard()).findAny();
        if (star.isPresent()) {
            set.removeIf(y -> y instanceof HostSource);
            set.add(star.get());
        }

        return set;
    }

    @Nonnull private static <T> Set<T> intersect(@Nonnull Set<T> a, @Nonnull Set<T> b) {
        Set<T> set = new LinkedHashSet<>();

        Iterator<T> aIterator = a.iterator();
        Iterator<T> bIterator = b.iterator();

        if (!aIterator.hasNext() || aIterator.next() == None.INSTANCE ||
            !bIterator.hasNext() || bIterator.next() == None.INSTANCE) {
            return set;
        }

        Optional<T> star = b.stream().filter(x -> x instanceof HostSource && ((HostSource) x).isWildcard()).findAny();
        if (star.isPresent()) {
            set.addAll(a);
            return set;
        }

        for (T x : a) {
            if (x instanceof HostSource && ((HostSource) x).isWildcard()) {
                set.clear();
                set.addAll(b);
                return set;
            }
            if (b.contains(x)) {
                set.add(x);
            }
        }

        return set;
    }

    @Nonnull public final Stream<Value> values() {
        return values.stream();
    }

    @Nonnull public abstract Directive<Value> construct(Set<Value> newValues);

    @SuppressWarnings("CloneDoesntCallSuperClone") @Nonnull @Override public final Directive<Value> clone() {
        Set<Value> s = new LinkedHashSet<>();
        s.addAll(this.values);
        return this.construct(s);
    }

    @Nonnull public final Directive<Value> bind(@Nonnull Function<Value, Set<? extends Value>> f) {
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

    public final void union(@Nonnull Directive<Value> other) {
        if (other.getClass() != this.getClass()) {
            throw new IllegalArgumentException(this.getClass() + " can be unioned with " + this.getClass() +
                ", but found " + other.getClass());
        }
        this.values = Directive.union(this.values, other.values);
    }

    public final void intersect(@Nonnull Directive<Value> other) {
        if (other.getClass() != this.getClass()) {
            throw new IllegalArgumentException(this.getClass() + " can be intersected with " + this.getClass() +
                ", but found " + other.getClass());
        }
        this.values = Directive.intersect(this.values, other.values);
    }

    boolean equalsHelper(@Nonnull Directive<Value> other) {
        return this.values().count() == other.values().count() && this.values()
            .allMatch((m) -> other.values().anyMatch((n) -> n.equals(m)));
    }

    int hashCodeHelper(int seed) {
        return this.values().map(Object::hashCode).reduce(seed, (a, b) -> a ^ b);
    }

    @Nonnull @Override public String show() {
        return Stream.concat(Stream.of(this.name), this.values().map(Show::show)).collect(Collectors.joining(" "));
    }

    public final boolean contains(@Nonnull DirectiveValue value) {
        return values().anyMatch(value::equals);
    }

    public final boolean sourceListEquals(@Nullable Object other) {
        return other != null && this.equalsHelper((Directive<Value>) other);
    }

    @SuppressWarnings("unchecked") @Override public final boolean equals(@Nullable Object other) {
        return other != null && other.getClass() == this.getClass() && this.equalsHelper((Directive<Value>) other);
    }

    @Override public final int hashCode() {
        return this.hashCodeHelper(this.getClass().getCanonicalName().hashCode());
    }
}
