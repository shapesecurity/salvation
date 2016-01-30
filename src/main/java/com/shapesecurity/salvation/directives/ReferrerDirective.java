package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.ReferrerValue;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.Set;

public class ReferrerDirective extends Directive<ReferrerValue> {
    @Nonnull private static final String NAME = "referrer";

    public ReferrerDirective(@Nonnull Set<ReferrerValue> values) {
        super(ReferrerDirective.NAME, values);
    }
    public ReferrerDirective(@Nonnull ReferrerValue v) {
        this(Collections.singleton(v));
    }

    @Nonnull @Override public Directive<ReferrerValue> construct(Set<ReferrerValue> newValues) {
        return new ReferrerDirective(newValues);
    }
}
