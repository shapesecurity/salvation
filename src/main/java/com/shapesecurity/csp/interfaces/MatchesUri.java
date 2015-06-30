package com.shapesecurity.csp.interfaces;

import com.shapesecurity.csp.data.Origin;
import com.shapesecurity.csp.data.URI;

import javax.annotation.Nonnull;

public interface MatchesUri {
    boolean matchesUri(@Nonnull Origin origin, @Nonnull URI uri);
}
