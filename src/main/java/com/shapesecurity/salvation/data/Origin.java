package com.shapesecurity.salvation.data;

import com.shapesecurity.salvation.interfaces.Show;

import javax.annotation.Nonnull;

public abstract class Origin implements Show {
    @Nonnull @Override public abstract String show();
}
