package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public class FormActionDirective extends SourceListDirective {
    @Nonnull private static final String name = "form-action";

    public FormActionDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(FormActionDirective.name, sourceExpressions);
    }

    @Nonnull @Override
    public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
        return new FormActionDirective(newValues);
    }
}
