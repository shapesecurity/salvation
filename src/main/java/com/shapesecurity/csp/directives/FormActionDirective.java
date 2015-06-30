package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;

public class FormActionDirective extends SourceListDirective {
    @Nonnull
    private static final String name = "form-action";

    public FormActionDirective(@Nonnull List<SourceExpression> sourceExpressions) {
        super(FormActionDirective.name, sourceExpressions);
    }
}
