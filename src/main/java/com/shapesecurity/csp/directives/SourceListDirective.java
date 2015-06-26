package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.Base64Value;
import com.shapesecurity.csp.URI;
import com.shapesecurity.csp.sources.HashSource;
import com.shapesecurity.csp.sources.MatchesHash;
import com.shapesecurity.csp.sources.MatchesUri;
import com.shapesecurity.csp.sources.SourceExpression;

import javax.annotation.Nonnull;
import java.util.List;

public abstract class SourceListDirective extends Directive<SourceExpression> {
    SourceListDirective(@Nonnull String name, @Nonnull List<SourceExpression> values) {
        super(name, values);
    }

    public boolean matchesHash(@Nonnull HashSource.HashAlgorithm algorithm, @Nonnull Base64Value hashValue) {
        return this.values()
          .filter(x -> x instanceof MatchesHash)
          .anyMatch(x -> ((MatchesHash) x).matchesHash(algorithm, hashValue));
    }

    public boolean matchesUri(@Nonnull URI origin, @Nonnull URI uri) {
        return this.values()
          .filter(x -> x instanceof MatchesUri)
          .anyMatch(x -> ((MatchesUri) x).matchesUri(origin, uri));
    }
}
