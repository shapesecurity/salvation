package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.Set;

public class FormActionDirective extends SourceListDirective {
    @Nonnull
    private static final String name = "form-action";

    public FormActionDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(FormActionDirective.name, sourceExpressions);
    }
}
