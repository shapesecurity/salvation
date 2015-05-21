package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.sources.SourceExpression;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.stream.Stream;

public abstract class SourceListDirective extends Directive<SourceExpression> {
    SourceListDirective(@Nonnull String name, @Nonnull List<SourceExpression> values) {
        super(name, values);
    }
}
