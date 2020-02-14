package ru.olegcherednik.zip4jvm.io.in.data;

import ru.olegcherednik.zip4jvm.io.in.file.SrcFile;
import ru.olegcherednik.zip4jvm.model.ZipModel;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 04.08.2019
 */
public class SingleZipInputStream extends BaseZipDataInput {

    public SingleZipInputStream(SrcFile srcFile) throws IOException {
        super(null, srcFile);
    }

    public SingleZipInputStream(ZipModel zipModel) throws IOException {
        super(zipModel, zipModel.getSrcFile());
    }

    @Override
    public int read(byte[] buf, int offs, int len) throws IOException {
        return delegate.read(buf, offs, len);
    }

}
