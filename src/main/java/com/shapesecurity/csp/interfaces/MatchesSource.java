package com.shapesecurity.csp.interfaces;

import com.shapesecurity.csp.data.GUID;
import com.shapesecurity.csp.data.Origin;
import com.shapesecurity.csp.data.URI;

import javax.annotation.Nonnull;

public interface MatchesSource {
    boolean matchesSource(@Nonnull Origin origin, @Nonnull URI source);
    boolean matchesSource(@Nonnull Origin origin, @Nonnull GUID source);
}
