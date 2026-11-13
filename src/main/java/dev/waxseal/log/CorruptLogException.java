package dev.waxseal.log;

import java.io.IOException;

/** The entry file is damaged in a way an interrupted write cannot explain. */
public final class CorruptLogException extends IOException {

    private static final long serialVersionUID = 1L;

    public CorruptLogException(String message) {
        super(message);
    }
}
