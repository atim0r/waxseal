package dev.waxseal.witness;

/** The log presented something an honest append-only log could never produce. */
public final class MisbehaviorException extends Exception {

    private static final long serialVersionUID = 1L;

    public enum Reason {
        /** The checkpoint is not signed by the key the witness pinned. */
        BAD_SIGNATURE,
        /** The checkpoint belongs to a different log. */
        WRONG_ORIGIN,
        /** The log claims to be smaller than a size it already committed to. */
        ROLLBACK,
        /** Two different histories were signed for the same size. */
        FORK,
        /** The new history does not contain the old one unchanged. */
        INCONSISTENT
    }

    private final Reason reason;

    public MisbehaviorException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
