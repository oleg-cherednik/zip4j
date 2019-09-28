package ru.olegcherednik.zip4jvm.io.in;

import org.apache.commons.io.IOUtils;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.out.SplitZipOutputStream;
import ru.olegcherednik.zip4jvm.model.ZipModel;

import java.io.IOException;
import java.nio.file.Path;

/**
 * @author Oleg Cherednik
 * @since 04.08.2019
 */
public class SplitZipInputStream extends BaseDataInput {

    protected final ZipModel zipModel;
    private long disk;

    public static SplitZipInputStream create(ZipModel zipModel, long disk) throws IOException {
        return new SplitZipInputStream(zipModel, disk);
    }

    private SplitZipInputStream(ZipModel zipModel, long disk) throws IOException {
        this.zipModel = zipModel;
        this.disk = disk;
        delegate = new LittleEndianReadFile(zipModel.getPartFile(disk));
        checkSignature();
    }

    private void checkSignature() throws IOException {
        if (disk == 0 && delegate.readSignature() != SplitZipOutputStream.SPLIT_SIGNATURE)
            throw new Zip4jvmException("Incorrect split file signature: " + zipModel.getFile().getFileName());
    }

    @Override
    @SuppressWarnings("PMD.AvoidReassigningParameters")
    public int read(byte[] buf, int offs, int len) throws IOException {
        int res = 0;

        while (res < len) {
            int total = delegate.read(buf, offs, len);

            if (total > 0)
                res += total;

            if (total == IOUtils.EOF || total < len) {
                openNextDisk();
                offs += Math.max(0, total);
                len -= Math.max(0, total);
            }
        }

        return res;
    }

    private void openNextDisk() throws IOException {
        Path splitFile = zipModel.getPartFile(++disk);
        delegate.close();
        delegate = new LittleEndianReadFile(splitFile);
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }

}
