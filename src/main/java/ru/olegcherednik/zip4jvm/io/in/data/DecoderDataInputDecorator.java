package ru.olegcherednik.zip4jvm.io.in.data;

import lombok.RequiredArgsConstructor;
import org.apache.commons.io.IOUtils;
import ru.olegcherednik.zip4jvm.crypto.Decoder;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 07.02.2020
 */
@RequiredArgsConstructor
public final class DecoderDataInputDecorator extends BaseDataInput implements DecoderDataInput {

    private final DataInput delegate;
    private final Decoder decoder;

    @Override
    public long getDataCompressedSize(long compressedSize) {
        return decoder.getDataCompressedSize(compressedSize);
    }

    @Override
    public void decodingAccomplished() throws IOException {
        decoder.close(delegate);
    }

    @Override
    public long getOffs() {
        return delegate.getOffs();
    }

    @Override
    public long length() throws IOException {
        return delegate.getOffs();
    }

    @Override
    public int read(byte[] buf, int offs, int len) throws IOException {
        len = delegate.read(buf, offs, len);

        if (len != IOUtils.EOF)
            decoder.decrypt(buf, offs, len);

        return len;
    }

    @Override
    public long toLong(byte[] buf, int offs, int len) {
        return delegate.toLong(buf, offs, len);
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }

    @Override
    public long skip(long bytes) throws IOException {
        return delegate.skip(bytes);
    }

    @Override
    public void seek(long pos) throws IOException {
        delegate.seek(pos);
    }

    @Override
    public String toString() {
        return delegate.toString();
    }

}
