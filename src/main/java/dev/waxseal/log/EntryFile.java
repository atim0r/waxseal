package dev.waxseal.log;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.zip.CRC32C;

/**
 * Append-only file of entries. Each record is {@code [int length][payload][int crc32c]}.
 *
 * <p>The checksum only catches accidents (bit rot, torn writes). It is not a security control:
 * anyone who can edit the file can also fix the checksum. Detecting that is the Merkle tree's job.
 */
final class EntryFile implements Closeable {

    private static final int OVERHEAD = 2 * Integer.BYTES;

    private final FileChannel channel;
    private final List<Long> offsets = new ArrayList<>();
    private long end;
    private boolean tornTail;

    private EntryFile(FileChannel channel) {
        this.channel = channel;
    }

    /** Opens the file and feeds every stored entry, in order, to {@code replay}. */
    static EntryFile open(Path file, Consumer<byte[]> replay) throws IOException {
        EntryFile entries = new EntryFile(FileChannel.open(file,
                StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE));
        try {
            entries.replay(replay);
            return entries;
        } catch (IOException | RuntimeException e) {
            entries.close();
            throw e;
        }
    }

    private void replay(Consumer<byte[]> replay) throws IOException {
        long fileSize = channel.size();
        while (end < fileSize) {
            byte[] payload = readRecord(end, fileSize);
            if (payload == null) {
                // A record that stops short of its declared length: an append interrupted by a crash.
                tornTail = true;
                return;
            }
            offsets.add(end);
            end += OVERHEAD + payload.length;
            replay.accept(payload);
        }
    }

    private byte[] readRecord(long position, long limit) throws IOException {
        if (limit - position < Integer.BYTES) {
            return null;
        }
        int length = readExact(position, Integer.BYTES).getInt();
        if (length < 0 || length > TransparencyLog.MAX_ENTRY_BYTES) {
            throw new CorruptLogException("entry " + offsets.size() + " has an invalid length");
        }
        if (limit - position < OVERHEAD + length) {
            return null;
        }
        ByteBuffer record = readExact(position + Integer.BYTES, length + Integer.BYTES);
        byte[] payload = new byte[length];
        record.get(payload);
        if (record.getInt() != checksum(payload)) {
            throw new CorruptLogException("entry " + offsets.size() + " fails its checksum");
        }
        return payload;
    }

    /**
     * Drops an interrupted trailing append. Kept separate from opening so the caller can first
     * check the file against its signed checkpoints: a file that fails that check is evidence and
     * must not be modified.
     */
    void discardTornTail() throws IOException {
        if (tornTail) {
            channel.truncate(end);
            channel.force(true);
            tornTail = false;
        }
    }

    long append(byte[] payload) throws IOException {
        ByteBuffer record = ByteBuffer.allocate(OVERHEAD + payload.length);
        record.putInt(payload.length).put(payload).putInt(checksum(payload)).flip();
        long position = end;
        while (record.hasRemaining()) {
            position += channel.write(record, position);
        }
        // The entry is acknowledged only after it is on stable storage.
        channel.force(false);
        offsets.add(end);
        end = position;
        return offsets.size() - 1;
    }

    byte[] read(long index) throws IOException {
        if (index < 0 || index >= offsets.size()) {
            throw new IllegalArgumentException("entry index out of range");
        }
        long position = offsets.get((int) index);
        int length = readExact(position, Integer.BYTES).getInt();
        byte[] payload = new byte[length];
        readExact(position + Integer.BYTES, length).get(payload);
        return payload;
    }

    private ByteBuffer readExact(long position, int length) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(length);
        while (buffer.hasRemaining()) {
            if (channel.read(buffer, position + buffer.position()) < 0) {
                throw new EOFException("unexpected end of entry file");
            }
        }
        return buffer.flip();
    }

    static int checksum(byte[] payload) {
        CRC32C crc = new CRC32C();
        crc.update(payload);
        return (int) crc.getValue();
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }
}
