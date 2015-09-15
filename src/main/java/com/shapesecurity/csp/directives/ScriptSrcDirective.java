package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public class ScriptSrcDirective extends SourceListDirective {
    @Nonnull private static final String NAME = "script-src";

    public ScriptSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
        super(ScriptSrcDirective.NAME, sourceExpressions);
    }

    @Nonnull @Override
    public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
        return new ScriptSrcDirective(newValues);
    }
}
