package ru.olegcherednik.zip4jvm.io.in.file;

import org.apache.commons.io.IOUtils;

import java.io.IOException;

import static java.util.Objects.requireNonNull;

/**
 * @author Oleg Cherednik
 * @since 22.01.2020
 */
public class LittleEndianSevenZipReadFile extends LittleEndianDataInputFile {

    private final SevenZipSplitSrcFile zip;
    private int itemPos;
    /** offs from the beginning of the first file */
    private long offs;

    protected LittleEndianSevenZipReadFile(SevenZipSplitSrcFile zip) throws IOException {
        super(zip.getItems().get(0).getFile());
        this.zip = zip;
        length = zip.getLength();
    }

    @Override
    public long skip(long bytes) throws IOException {
        int skipped = 0;

        for (int i = itemPos; skipped < bytes; ) {
            SrcFile.Item item = requireNonNull(zip.getDisk(i));
            boolean withinDisk = bytes - skipped < item.getLength();

            if (withinDisk || zip.isLast(item)) {
                if (i != itemPos) {
                    openNextItem(item.getFile());
                    itemPos = item.getPos();
                }

                skipped += super.skip(bytes - skipped);
                break;
            }

            skipped += item.getLength();
        }

        return skipped;
    }

    @Override
    public void seek(long pos) throws IOException {
        for (SrcFile.Item item : zip.getItems()) {
            if (item.getOffs() + item.getLength() < pos && !zip.isLast(item))
                continue;

            if (itemPos != item.getPos())
                openNextItem(item.getFile());

            super.seek(pos - item.getOffs());
            itemPos = item.getPos();
            offs = item.getOffs();
            break;
        }
    }

    @Override
    public int read(byte[] buf, int offs, int len) throws IOException {
        int res = 0;
        int size = len;

        while (res < len) {
            int total = in.read(buf, offs, size);

            if (total > 0)
                res += total;

            if (total == IOUtils.EOF || total < size) {
                openNextItem(requireNonNull(zip.getDisk(++itemPos)).getFile());
                offs += Math.max(0, total);
                size -= Math.max(0, total);
            }
        }

        return res;
    }

    @Override
    public long getOffs() {
        try {
            return offs + in.getFilePointer();
        } catch(IOException e) {
            return IOUtils.EOF;
        }
    }

}
