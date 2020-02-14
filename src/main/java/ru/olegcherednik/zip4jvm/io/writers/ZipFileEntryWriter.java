package ru.olegcherednik.zip4jvm.io.writers;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.ZipFile;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;
import ru.olegcherednik.zip4jvm.io.out.entry.EntryOutputStream;
import ru.olegcherednik.zip4jvm.model.ZipModel;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntryBuilder;
import ru.olegcherednik.zip4jvm.model.settings.ZipEntrySettings;
import ru.olegcherednik.zip4jvm.utils.ZipUtils;
import ru.olegcherednik.zip4jvm.utils.function.Writer;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 19.09.2019
 */
@RequiredArgsConstructor
public final class ZipFileEntryWriter implements Writer {

    private final ZipFile.Entry entry;
    private final ZipEntrySettings entrySettings;
    private final ZipModel tempZipModel;

    @Override
    public void write(DataOutput out) throws IOException {
        ZipEntry zipEntry = ZipEntryBuilder.build(entry, entrySettings);
        ZipUtils.copyLarge(zipEntry.getInputStream(), EntryOutputStream.create(zipEntry, tempZipModel, out));
    }

    @Override
    public String toString() {
        return '+' + ZipUtils.getFileName(entry);
    }
}
