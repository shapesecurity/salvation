package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.data.URI;
import com.shapesecurity.salvation.directiveValues.ReportToValue;

import javax.annotation.Nonnull;
import java.util.Set;

public class ReportToDirective extends Directive<ReportToValue> {
    @Nonnull private static final String NAME = "report-to";

    public ReportToDirective(@Nonnull Set<ReportToValue> tokens) {
        super(ReportToDirective.NAME, tokens);
    }

    @Nonnull @Override public Directive<ReportToValue> construct(Set<ReportToValue> newValues) {
        return new ReportToDirective(newValues);
    }
}
