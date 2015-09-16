package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.data.Base64Value;
import com.shapesecurity.csp.data.Origin;
import com.shapesecurity.csp.data.URI;
import com.shapesecurity.csp.directiveValues.HashSource;
import com.shapesecurity.csp.directiveValues.HostSource;
import com.shapesecurity.csp.directiveValues.KeywordSource;
import com.shapesecurity.csp.directiveValues.SourceExpression;
import com.shapesecurity.csp.interfaces.MatchesHash;
import com.shapesecurity.csp.interfaces.MatchesNonce;
import com.shapesecurity.csp.interfaces.MatchesUri;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.Set;

public abstract class SourceListDirective extends Directive<SourceExpression>
    implements MatchesUri, MatchesHash, MatchesNonce {
    SourceListDirective(@Nonnull String name, @Nonnull Set<SourceExpression> values) {
        super(name, values);
    }

    public boolean matchesHash(@Nonnull HashSource.HashAlgorithm algorithm,
        @Nonnull Base64Value hashValue) {
        return this.values().filter(x -> x instanceof MatchesHash)
            .anyMatch(x -> ((MatchesHash) x).matchesHash(algorithm, hashValue));
    }

    public boolean matchesUri(@Nonnull Origin origin, @Nonnull URI uri) {
        return this.values().filter(x -> x instanceof MatchesUri)
            .anyMatch(x -> ((MatchesUri) x).matchesUri(origin, uri));
    }

    public boolean matchesNonce(@Nonnull String nonce) {
        return this.values().filter(x -> x instanceof MatchesNonce)
            .anyMatch(x -> ((MatchesNonce) x).matchesNonce(nonce));
    }

    @Nonnull public Directive<SourceExpression> resolveSelf(@Nonnull Origin origin) {
        return this.bind(dv ->
            dv == KeywordSource.Self
                ? Collections.singleton(new HostSource(origin.scheme, origin.host, origin.port, null))
                : null
        );
    }
}
