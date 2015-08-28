package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.data.Base64Value;
import com.shapesecurity.csp.data.Origin;
import com.shapesecurity.csp.data.URI;
import com.shapesecurity.csp.directiveValues.HashSource;
import com.shapesecurity.csp.directiveValues.SourceExpression;
import com.shapesecurity.csp.interfaces.MatchesHash;
import com.shapesecurity.csp.interfaces.MatchesNonce;
import com.shapesecurity.csp.interfaces.MatchesUri;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.Set;

public abstract class SourceListDirective extends Directive<SourceExpression> implements MatchesUri, MatchesHash, MatchesNonce {
    SourceListDirective(@Nonnull String name, @Nonnull Set<SourceExpression> values) {
        super(name, values);
    }

    public boolean matchesHash(@Nonnull HashSource.HashAlgorithm algorithm, @Nonnull Base64Value hashValue) {
        return this.values()
          .filter(x -> x instanceof MatchesHash)
          .anyMatch(x -> ((MatchesHash) x).matchesHash(algorithm, hashValue));
    }

    public boolean matchesUri(@Nonnull Origin origin, @Nonnull URI uri) {
        return this.values()
          .filter(x -> x instanceof MatchesUri)
          .anyMatch(x -> ((MatchesUri) x).matchesUri(origin, uri));
    }

    public boolean matchesNonce(@Nonnull Base64Value nonce) {
        return this.values()
            .filter(x -> x instanceof MatchesNonce)
            .anyMatch(x -> ((MatchesNonce) x).matchesNonce(nonce));
    }
}
