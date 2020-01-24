package ru.olegcherednik.zip4jvm.io.in;

import ru.olegcherednik.zip4jvm.model.ZipModel;

import java.io.IOException;
import java.nio.file.Path;

/**
 * @author Oleg Cherednik
 * @since 04.08.2019
 */
public class SingleZipInputStream extends BaseZipDataInput {

    public SingleZipInputStream(Path zip) throws IOException {
        super(new SingleZip(zip));
    }

    public SingleZipInputStream(Zip zip) throws IOException {
        super(zip);
    }

    public SingleZipInputStream(ZipModel zipModel) throws IOException {
        this(zipModel.getFile());
    }

    @Override
    public int read(byte[] buf, int offs, int len) throws IOException {
        int res = delegate.read(buf, offs, len);
        cycleBuffer.write(buf, offs, len);
        return res;
    }

    @Override
    public void skip(long bytes) throws IOException {
        while (bytes > 0) {
            int actual = delegate.skip((int)Math.min(Integer.MAX_VALUE, bytes));
            bytes -= actual;

            if (actual == 0)
                break;
        }
    }

    @Override
    public ZipModel getZipModel() {
        return null;
    }
}
