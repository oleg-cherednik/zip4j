package ru.olegcherednik.zip4jvm.io.out.data;

import ru.olegcherednik.zip4jvm.io.out.file.LittleEndianWriteFile;
import ru.olegcherednik.zip4jvm.io.out.file.DataOutputFile;
import ru.olegcherednik.zip4jvm.model.ZipModel;

import java.io.IOException;
import java.nio.file.Path;

/**
 * @author Oleg Cherednik
 * @since 11.02.2020
 */
abstract class BaseZipDataOutput extends BaseDataOutput {

    protected final ZipModel zipModel;
    private DataOutputFile delegate;

    protected BaseZipDataOutput(ZipModel zipModel) throws IOException {
        this.zipModel = zipModel;
        createFile(zipModel.getSrcFile().getPath());
    }

    protected void createFile(Path zip) throws IOException {
        delegate = new LittleEndianWriteFile(zip);
    }

    @Override
    public void fromLong(long val, byte[] buf, int offs, int len) {
        delegate.fromLong(val, buf, offs, len);
    }

    @Override
    public final long getOffs() {
        return delegate.getOffs();
    }

    @Override
    protected void writeInternal(byte[] buf, int offs, int len) throws IOException {
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
