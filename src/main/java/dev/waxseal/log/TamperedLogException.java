package dev.waxseal.log;

import java.io.IOException;

/** The stored entries contradict a checkpoint this log signed earlier. */
public final class TamperedLogException extends IOException {

    private static final long serialVersionUID = 1L;

    public TamperedLogException(String message) {
        super(message);
    }
}
