package ru.olegcherednik.zip4jvm.io.in.data;

import lombok.Getter;
import lombok.Setter;
import ru.olegcherednik.zip4jvm.io.in.file.DataInputFile;
import ru.olegcherednik.zip4jvm.io.in.file.SrcFile;
import ru.olegcherednik.zip4jvm.model.ZipModel;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 12.12.2019
 */
@Getter
abstract class BaseZipDataInput extends BaseDataInput implements ZipDataInput {

    protected final ZipModel zipModel;
    protected DataInputFile delegate;
    @Setter
    protected String fileName;

    protected BaseZipDataInput(ZipModel zipModel, SrcFile srcFile) throws IOException {
        this.zipModel = zipModel;
        delegate = srcFile.dataInputFile();
        fileName = srcFile.getPath().getFileName().toString();
    }

    @Override
    public long getOffs() {
        return delegate.getOffs();
    }

    @Override
    public long length() throws IOException {
        return delegate.length();
    }

    @Override
    public void seek(long pos) throws IOException {
        delegate.seek(pos);
    }

    @Override
    public long skip(long bytes) throws IOException {
        return delegate.skip(bytes);
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }

    @Override
    public long toLong(byte[] buf, int offs, int len) {
        return delegate.toLong(buf, offs, len);
    }

    @Override
    public String toString() {
        return delegate.toString();
    }

}
