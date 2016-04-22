package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.ReportToValue;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.Set;

public class ReportToDirective extends Directive<ReportToValue> {
    @Nonnull private static final String NAME = "report-to";

    public ReportToDirective(@Nonnull Set<ReportToValue> values) {
        super(ReportToDirective.NAME, values);
    }

    public ReportToDirective(@Nonnull ReportToValue v) {
        this(Collections.singleton(v));
    }

    @Nonnull @Override public Directive<ReportToValue> construct(Set<ReportToValue> newValues) {
        return new ReportToDirective(newValues);
    }
}
