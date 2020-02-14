package ru.olegcherednik.zip4jvm.model.builders;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.exception.Zip4jvmException;
import ru.olegcherednik.zip4jvm.io.in.file.SrcFile;
import ru.olegcherednik.zip4jvm.io.readers.ZipModelReader;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;
import ru.olegcherednik.zip4jvm.model.Charsets;
import ru.olegcherednik.zip4jvm.model.EndCentralDirectory;
import ru.olegcherednik.zip4jvm.model.Zip64;
import ru.olegcherednik.zip4jvm.model.ZipModel;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntryBuilder;
import ru.olegcherednik.zip4jvm.model.settings.ZipSettings;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Function;

/**
 * @author Oleg Cherednik
 * @since 01.09.2019
 */
@RequiredArgsConstructor
public final class ZipModelBuilder {

    private final SrcFile srcFile;
    private final EndCentralDirectory endCentralDirectory;
    private final Zip64 zip64;
    private final CentralDirectory centralDirectory;
    private final Function<Charset, Charset> charsetCustomizer;

    public static ZipModel read(SrcFile srcFile) throws IOException {
        return read(srcFile, Charsets.UNMODIFIED);
    }

    public static ZipModel read(SrcFile srcFile, Function<Charset, Charset> charsetCustomizer) throws IOException {
        return new ZipModelReader(srcFile, charsetCustomizer).read();
    }

    public static ZipModel build(Path zip, ZipSettings settings) {
        if (Files.exists(zip))
            throw new Zip4jvmException("ZipFile '" + zip.toAbsolutePath() + "' exists");

        ZipModel zipModel = new ZipModel(SrcFile.of(zip));
        zipModel.setSplitSize(settings.getSplitSize());
        zipModel.setComment(settings.getComment());
        zipModel.setZip64(settings.isZip64());

        return zipModel;
    }

    public ZipModel build() throws IOException {
        ZipModel zipModel = new ZipModel(srcFile);

        zipModel.setZip64(zip64 != Zip64.NULL);
        zipModel.setComment(endCentralDirectory.getComment());
        zipModel.setTotalDisks(getTotalDisks());
        zipModel.setMainDisk(getMainDisks());
        zipModel.setCentralDirectorySize(getCentralDirectorySize());
        zipModel.setCentralDirectoryOffs(getCentralDirectoryOffs(endCentralDirectory, zip64));
        createAndAddEntries(zipModel);
        updateSplit(zipModel);

        return zipModel;
    }

    private void createAndAddEntries(ZipModel zipModel) {
        centralDirectory.getFileHeaders().stream()
                        .map(fileHeader -> ZipEntryBuilder.build(fileHeader, zipModel, charsetCustomizer))
                        .forEach(zipModel::addEntry);
    }

    private long getTotalDisks() {
        if (zip64 == Zip64.NULL)
            return endCentralDirectory.getTotalDisks();
        return zip64.getEndCentralDirectory().getTotalDisks();
    }

    private long getMainDisks() {
        if (zip64 == Zip64.NULL)
            return endCentralDirectory.getMainDisk();
        return zip64.getEndCentralDirectoryLocator().getMainDisk();
    }

    public long getCentralDirectorySize() {
        if (zip64 == Zip64.NULL)
            return endCentralDirectory.getCentralDirectorySize();
        return zip64.getEndCentralDirectory().getCentralDirectorySize();
    }

    public static long getCentralDirectoryOffs(EndCentralDirectory endCentralDirectory, Zip64 zip64) {
        if (zip64 == Zip64.NULL)
            return endCentralDirectory.getCentralDirectoryOffs();
        return zip64.getEndCentralDirectory().getCentralDirectoryOffs();
    }

    public static long getTotalEntries(EndCentralDirectory endCentralDirectory, Zip64 zip64) {
        if (zip64 == Zip64.NULL)
            return endCentralDirectory.getTotalEntries();
        return zip64.getEndCentralDirectory().getTotalEntries();
    }

    private static void updateSplit(ZipModel zipModel) throws IOException {
        if (zipModel.getSrcFile().isSplit())
            zipModel.setSplitSize(getSplitSize(zipModel));
    }

    private static long getSplitSize(ZipModel zipModel) throws IOException {
        long size = 0;

        for (long i = 0; i <= zipModel.getTotalDisks(); i++)
            size = Math.max(size, Files.size(zipModel.getDiskFile(i)));

        return size;
    }

}
