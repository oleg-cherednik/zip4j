package ru.olegcherednik.zip4jvm.io.out.data;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.crypto.Encoder;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 11.02.2020
 */
@RequiredArgsConstructor
public final class DecoderDataOutputDecorator extends BaseDataOutput implements DecoderDataOutput {

    private final DataOutput delegate;
    private final Encoder encoder;

    @Override
    public void writeEncryptionHeader() throws IOException {
        encoder.writeEncryptionHeader(delegate);
    }

    @Override
    public void encodingAccomplished() throws IOException {
        encoder.close(delegate);
    }

    @Override
    public void fromLong(long val, byte[] buf, int offs, int len) {
        delegate.fromLong(val, buf, offs, len);
    }

    @Override
    public long getOffs() {
        return delegate.getOffs();
    }

    @Override
    protected void writeInternal(byte[] buf, int offs, int len) throws IOException {
        encoder.encrypt(buf, offs, len);
        delegate.write(buf, offs, len);
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }

    @Override
    public String toString() {
        return delegate.toString();
    }

}
