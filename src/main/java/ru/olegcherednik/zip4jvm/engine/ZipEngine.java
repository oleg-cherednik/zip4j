package ru.olegcherednik.zip4jvm.engine;

import ru.olegcherednik.zip4jvm.ZipFile;
import ru.olegcherednik.zip4jvm.exception.EntryDuplicationException;
import ru.olegcherednik.zip4jvm.exception.EntryNotFoundException;
import ru.olegcherednik.zip4jvm.io.in.file.SrcFile;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;
import ru.olegcherednik.zip4jvm.io.out.data.SingleZipOutputStream;
import ru.olegcherednik.zip4jvm.io.out.data.SplitZipOutputStream;
import ru.olegcherednik.zip4jvm.io.writers.ExistedEntryWriter;
import ru.olegcherednik.zip4jvm.io.writers.ZipFileEntryWriter;
import ru.olegcherednik.zip4jvm.model.ZipModel;
import ru.olegcherednik.zip4jvm.model.builders.ZipModelBuilder;
import ru.olegcherednik.zip4jvm.model.settings.ZipEntrySettings;
import ru.olegcherednik.zip4jvm.model.settings.ZipSettings;
import ru.olegcherednik.zip4jvm.utils.ZipUtils;
import ru.olegcherednik.zip4jvm.utils.function.Writer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import static ru.olegcherednik.zip4jvm.utils.ValidationUtils.requireNotBlank;
import static ru.olegcherednik.zip4jvm.utils.ValidationUtils.requireNotNull;

/**
 * @author Oleg Cherednik
 * @since 09.09.2019
 */
public final class ZipEngine implements ZipFile.Writer {

    private final Path zip;
    private final ZipModel tempZipModel;
    private final Function<String, ZipEntrySettings> entrySettingsProvider;
    private final Map<String, Writer> fileNameWriter = new LinkedHashMap<>();

    public ZipEngine(Path zip, ZipSettings settings) throws IOException {
        this.zip = zip;
        tempZipModel = createTempZipModel(zip, settings, fileNameWriter);
        entrySettingsProvider = settings.getEntrySettingsProvider();
    }

    @Override
    public void add(ZipFile.Entry entry) {
        ZipEntrySettings entrySettings = entrySettingsProvider.apply(entry.getFileName());
        String fileName = ZipUtils.getFileName(entry);

        if (fileNameWriter.put(ZipUtils.getFileName(entry), new ZipFileEntryWriter(entry, entrySettings, tempZipModel)) != null)
            throw new EntryDuplicationException(fileName);
    }

    @Override
    public void removeEntryByName(String entryName) {
        requireNotBlank(entryName, "ZipEngine.entryName");

        entryName = ZipUtils.getFileNameNoDirectoryMarker(entryName);

        if (fileNameWriter.remove(entryName) != null)
            return;
        if (fileNameWriter.remove(entryName + '/') != null)
            return;
        throw new EntryNotFoundException(entryName);
    }

    @Override
    public void removeEntryByNamePrefix(String entryNamePrefix) {
        requireNotBlank(entryNamePrefix, "ZipEngine.entryNamePrefix");

        String normalizedPrefixEntryName = ZipUtils.normalizeFileName(entryNamePrefix);

        Set<String> entryNames = fileNameWriter.keySet().stream()
                                               .filter(entryName -> entryName.startsWith(normalizedPrefixEntryName))
                                               .collect(Collectors.toSet());

        if (entryNames.isEmpty())
            throw new EntryNotFoundException(entryNamePrefix);

        entryNames.forEach(fileNameWriter::remove);
    }

    @Override
    public void copy(Path zip) throws IOException {
        requireNotNull(zip, "ZipEngine.zip");

        ZipModel srcZipModel = ZipModelBuilder.read(SrcFile.of(zip));

        for (String fileName : srcZipModel.getEntryNames()) {
            if (fileNameWriter.containsKey(fileName))
                throw new EntryDuplicationException(fileName);

            char[] password = entrySettingsProvider.apply(fileName).getPassword();
            fileNameWriter.put(fileName, new ExistedEntryWriter(srcZipModel, fileName, tempZipModel, password));
        }
    }

    @Override
    public void setComment(String comment) {
        tempZipModel.setComment(comment);
    }

    @Override
    public void close() throws IOException {
        createTempZipFiles();
        removeOriginalZipFiles();
        moveTempZipFiles();
    }

    private void createTempZipFiles() throws IOException {
        try (DataOutput out = creatDataOutput(tempZipModel)) {
            for (Writer writer : fileNameWriter.values())
                writer.write(out);
        }
    }

    private void removeOriginalZipFiles() throws IOException {
        if (Files.exists(zip)) {
            ZipModel zipModel = ZipModelBuilder.read(SrcFile.of(zip));

            for (long i = 0; i <= zipModel.getTotalDisks(); i++)
                Files.deleteIfExists(zipModel.getDiskFile(i));
        }
    }

    private void moveTempZipFiles() throws IOException {
        for (long i = 0; i <= tempZipModel.getTotalDisks(); i++) {
            Path src = tempZipModel.getDiskFile(i);
            Path dest = zip.getParent().resolve(src.getFileName());
            Files.move(src, dest);
        }

        Files.deleteIfExists(tempZipModel.getSrcFile().getPath().getParent());
    }

    private static ZipModel createTempZipModel(Path zip, ZipSettings settings, Map<String, Writer> fileNameWriter) throws IOException {
        Path tempZip = createTempZip(zip);
        ZipModel tempZipModel = ZipModelBuilder.build(tempZip, settings);

        if (Files.exists(zip)) {
            ZipModel zipModel = ZipModelBuilder.read(SrcFile.of(zip));

            if (zipModel.isSplit())
                tempZipModel.setSplitSize(zipModel.getSplitSize());
            if (zipModel.getComment() != null)
                tempZipModel.setComment(zipModel.getComment());
            if (zipModel.isZip64())
                tempZipModel.setZip64(zipModel.isZip64());

            zipModel.getEntryNames().forEach(entryName -> {
                char[] password = settings.getEntrySettingsProvider().apply(entryName).getPassword();
                fileNameWriter.put(entryName, new ExistedEntryWriter(zipModel, entryName, tempZipModel, password));
            });
        }

        return tempZipModel;
    }

    private static Path createTempZip(Path zip) throws IOException {
        Path dir = zip.getParent().resolve("tmp");
        Files.createDirectories(dir);
        return dir.resolve(zip.getFileName());
    }

    private static DataOutput creatDataOutput(ZipModel zipModel) throws IOException {
        return zipModel.isSplit() ? new SplitZipOutputStream(zipModel) : new SingleZipOutputStream(zipModel);
    }

}
