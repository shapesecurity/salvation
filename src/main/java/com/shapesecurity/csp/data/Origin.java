package com.shapesecurity.csp.data;

import com.shapesecurity.csp.Constants;
import com.shapesecurity.csp.interfaces.Show;

import javax.annotation.Nonnull;
import java.util.Objects;

public abstract class Origin implements Show {
    @Nonnull @Override public abstract String show();
}
