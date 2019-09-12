package ru.olegcherednik.zip4jvm.utils;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.exception.Zip4jException;
import ru.olegcherednik.zip4jvm.io.out.DataOutput;
import ru.olegcherednik.zip4jvm.io.out.DataOutputStreamDecorator;
import ru.olegcherednik.zip4jvm.io.out.SingleZipOutputStream;
import ru.olegcherednik.zip4jvm.model.ZipModel;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public final class RemoveEntryFunc implements Consumer<Collection<String>> {

    @NonNull
    private final ZipModel zipModel;

    public void accept(@NonNull String entryName) {
        accept(Collections.singleton(entryName));
    }

    @Override
    public void accept(@NonNull Collection<String> entries) {
        entries = getExistedEntries(entries);

        if (entries.isEmpty())
            return;

        Path tmpZipFile = createTempFile();

        try (DataOutput out = SingleZipOutputStream.create(tmpZipFile, zipModel)) {
            writeFileHeaders(new DataOutputStreamDecorator(out), entries);
        } catch(IOException e) {
            throw new Zip4jException(e);
        }

        restoreFileName(tmpZipFile);
    }

    private Set<String> getExistedEntries(Collection<String> entryNames) {
        return entryNames.stream()
                         .filter(Objects::nonNull)
                         .map(entryName -> ZipUtils.normalizeFileName(entryName.toLowerCase()))
                         .map(entryName -> zipModel.getEntries().stream()
                                                   .filter(entry -> entry.getFileName().equalsIgnoreCase(entryName))
                                                   .map(ZipEntry::getFileName)
                                                   .collect(Collectors.toList()))
                         .flatMap(List::stream)
                         .collect(Collectors.toSet());
    }

    private Path createTempFile() {
        try {
            return Files.createTempFile(zipModel.getFile().getParent(), null, ".zip");
        } catch(IOException e) {
            throw new Zip4jException(e);
        }
    }

    private void writeFileHeaders(OutputStream out, Collection<String> entries) throws IOException {
//        List<ZipEntry> zipEntries = new ArrayList<>();
//        ZipEntry prv = null;
//
//        long offsIn = 0;
//        long offsOut = 0;
//        long skip = 0;
//
//        try (InputStream in = new FileInputStream(zipModel.getZip().toFile())) {
//            int total = zipModel.getEntries().size();
//
//            for (int i = 0; i < total; i++) {
//                ZipEntry zipEntry = zipModel.getEntries().get(i);
//
//                if (prv != null) {
//                    long curOffs = offsOut;
//                    long length = zipEntry.getLocalFileHeaderOffs() - prv.getLocalFileHeaderOffs();
//                    offsIn += skip + IOUtils.copyLarge(in, out, skip, length);
//                    offsOut += length;
//                    zipEntries.add(prv);
//                    prv.setLocalFileHeaderOffs(curOffs);
//                    skip = 0;
//
//                    // TODO fix offs for zip64
//
//                    //                long offsetLocalHdr = fileHeader.getOffsLocalFileHeader();
////                if (fileHeader.getZip64ExtendedInfo() != null &&
////                        fileHeader.getZip64ExtendedInfo().getOffsLocalHeaderRelative() != -1) {
////                    offsetLocalHdr = fileHeader.getZip64ExtendedInfo().getOffsLocalHeaderRelative();
////                }
////
////                fileHeader.setOffsLocalFileHeader(offsetLocalHdr - (offs - offsetLocalFileHeader) - 1);
//                }
//
//                if (entries.contains(zipEntry.getFileName())) {
//                    prv = null;
//                } else {
//                    prv = zipEntry;
//                }
//
//                skip = zipEntry.getLocalFileHeaderOffs() - offsIn;
//            }
//
//            if (prv != null) {
//                long curOffs = offsOut;
//                long length = zipModel.getCentralDirectoryOffs() - prv.getLocalFileHeaderOffs();
//                offsOut += IOUtils.copyLarge(in, out, skip, length);
//                zipEntries.add(prv);
//                prv.setLocalFileHeaderOffs(curOffs);
//            }
//        }
//
//        zipModel.getEntries().clear();
//        zipModel.getEntries().addAll(zipEntries);
    }

    private void restoreFileName(Path tmpZipFileName) {
        try {
            if (tmpZipFileName == null)
                return;
            if (Files.deleteIfExists(zipModel.getFile()))
                Files.move(tmpZipFileName, zipModel.getFile());
            else
                throw new Zip4jException("cannot delete old zip file");
        } catch(IOException e) {
            throw new Zip4jException(e);
        }
    }
}
