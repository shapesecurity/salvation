package com.shapesecurity.csp.interfaces;

import com.shapesecurity.csp.directiveValues.MediaType;

import javax.annotation.Nonnull;

public interface MatchesMediaType {
    boolean matchesMediaType(@Nonnull MediaType mediaType);
}
