package dev.waxseal.log;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/** Test helpers that damage a log directory the way an attacker or a failing disk would. */
public final class LogFiles {

    private LogFiles() {
    }

    public static Path entries(Path logDirectory) {
        return logDirectory.resolve("entries.dat");
    }

    public static Path checkpoints(Path logDirectory) {
        return logDirectory.resolve("checkpoints.txt");
    }

    /** Replaces an entry in place and repairs its checksum, leaving a healthy-looking file. */
    public static void rewriteEntry(Path logDirectory, String original, String replacement) throws IOException {
        byte[] from = original.getBytes(StandardCharsets.UTF_8);
        byte[] to = replacement.getBytes(StandardCharsets.UTF_8);
        if (from.length != to.length) {
            throw new IllegalArgumentException("replacement must keep the entry length");
        }
        byte[] content = Files.readAllBytes(entries(logDirectory));
        int position = indexOf(content, from);
        System.arraycopy(to, 0, content, position, to.length);
        ByteBuffer.wrap(content).putInt(position + to.length, EntryFile.checksum(to));
        Files.write(entries(logDirectory), content);
    }

    /** Flips one bit inside an entry without touching its checksum, like a failing disk. */
    public static void flipBitInside(Path logDirectory, String entry) throws IOException {
        byte[] content = Files.readAllBytes(entries(logDirectory));
        content[indexOf(content, entry.getBytes(StandardCharsets.UTF_8))] ^= 0x01;
        Files.write(entries(logDirectory), content);
    }

    /** Cuts the entry file so that it ends right before the given entry's record. */
    public static void truncateBefore(Path logDirectory, String entry) throws IOException {
        byte[] content = Files.readAllBytes(entries(logDirectory));
        int recordStart = indexOf(content, entry.getBytes(StandardCharsets.UTF_8)) - Integer.BYTES;
        Files.write(entries(logDirectory), Arrays.copyOf(content, recordStart));
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            if (Arrays.equals(haystack, i, i + needle.length, needle, 0, needle.length)) {
                return i;
            }
        }
        throw new IllegalArgumentException("entry not found in file");
    }
}
