package ru.olegcherednik.zip4jvm.io.in.data;

import lombok.Getter;
import org.apache.commons.io.IOUtils;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.in.file.LittleEndianReadFile;
import ru.olegcherednik.zip4jvm.io.in.file.SrcFile;
import ru.olegcherednik.zip4jvm.io.out.data.SplitZipOutputStream;
import ru.olegcherednik.zip4jvm.model.ZipModel;

import java.io.IOException;
import java.nio.file.Path;

/**
 * @author Oleg Cherednik
 * @since 22.01.2020
 */
public class SplitZipInputStream extends BaseZipDataInput {

    @Getter
    protected long disk;

    public SplitZipInputStream(ZipModel zipModel, long disk) throws IOException {
        super(zipModel, SrcFile.of(zipModel.getDiskFile(disk)));
        this.disk = disk;
        checkSignature();
    }

    private void checkSignature() throws IOException {
        if (disk != 0)
            return;

        byte[] buf = THREAD_LOCAL_BUF.get();
        read(buf, 0, 4);
        int signature = (int)delegate.toLong(buf, 0, 4);

        if (signature != SplitZipOutputStream.SPLIT_SIGNATURE)
            throw new Zip4jvmException("Incorrect split file signature: " + zipModel.getSrcFile().getPath());
    }

    @Override
    @SuppressWarnings("PMD.AvoidReassigningParameters")
    public int read(byte[] buf, int offs, final int len) throws IOException {
        int res = 0;
        int size = len;

        while (res < len) {
            int total = delegate.read(buf, offs, size);

            if (total > 0)
                res += total;

            if (total == IOUtils.EOF || total < size) {
                openNextDisk();
                offs += Math.max(0, total);
                size -= Math.max(0, total);
            }
        }

        return res;
    }

    @Override
    public long skip(long bytes) throws IOException {
        long skipped = 0;

        while (bytes > 0) {
            long actual = delegate.skip(bytes);

            skipped += actual;
            bytes -= actual;

            if (actual < bytes)
                openNextDisk();
        }

        return skipped;
    }

    private void openNextDisk() throws IOException {
        delegate.close();

        Path splitFile = zipModel.getDiskFile(++disk);
        delegate = new LittleEndianReadFile(splitFile);
        fileName = splitFile.getFileName().toString();
    }

    @Override
    public final String toString() {
        return "disk: " + disk + ", " + super.toString();
    }

}
