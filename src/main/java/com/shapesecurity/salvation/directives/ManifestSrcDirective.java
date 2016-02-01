package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public class ManifestSrcDirective extends SourceListDirective {
    @Nonnull private static final String name = "manifest-src";

    public ManifestSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(ManifestSrcDirective.name, sourceExpressions);
    }

    @Nonnull @Override public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
        return new ManifestSrcDirective(newValues);
    }
}
