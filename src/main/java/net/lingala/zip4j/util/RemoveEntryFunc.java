/*
 * Copyright 2010 Srikanth Reddy Lingala
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.lingala.zip4j.util;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import net.lingala.zip4j.core.HeaderWriter;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.model.CentralDirectory;
import net.lingala.zip4j.model.ZipModel;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public final class RemoveEntryFunc implements Consumer<Collection<String>> {
    @NonNull
    private final ZipModel zipModel;
    private final Function<Collection<String>, Set<String>> normalize = entries -> entries.stream()
                                                                                          .map(entryName -> FilenameUtils.normalize(entryName, true))
                                                                                          .collect(Collectors.toSet());

    public void accept(@NonNull String entryName) {
        accept(Collections.singleton(entryName));
    }

    @Override
    public void accept(@NonNull Collection<String> removeEntries) {
        if (removeEntries.isEmpty())
            return;

        Path tmpZipFile = createTempFile();

        try (OutputStream out = new FileOutputStream(tmpZipFile.toFile())) {
            writeFileHeaders(out, normalize.apply(removeEntries));
            new HeaderWriter().finalizeZipFile(zipModel, out);
        } catch(IOException e) {
            throw new ZipException(e);
        }

        restoreFileName(tmpZipFile);
    }

    private Path createTempFile() {
        try {
            return Files.createTempFile(zipModel.getZipFile().getParent(), null, ".zip");
        } catch(IOException e) {
            throw new ZipException(e);
        }
    }

    private void writeFileHeaders(OutputStream out, Collection<String> removeEntries) throws IOException {
        List<CentralDirectory.FileHeader> fileHeaders = new ArrayList<>();
        CentralDirectory.FileHeader prv = null;

        long offsIn = 0;
        long offsOut = 0;
        long skip = 0;

        try (InputStream in = new FileInputStream(zipModel.getZipFile().toFile())) {
            for (CentralDirectory.FileHeader header : zipModel.getFileHeaders()) {
                if (prv != null) {
                    long curOffs = offsOut;
                    long length = header.getOffsLocalFileHeader() - prv.getOffsLocalFileHeader();
                    offsIn += skip + IOUtils.copyLarge(in, out, skip, length);
                    offsOut += length;
                    fileHeaders.add(prv);
                    prv.setOffsLocalFileHeader(curOffs);
                    skip = 0;

                    // TODO fix offs for zip64

                    //                long offsetLocalHdr = fileHeader.getOffsLocalFileHeader();
//                if (fileHeader.getZip64ExtendedInfo() != null &&
//                        fileHeader.getZip64ExtendedInfo().getOffsLocalHeaderRelative() != -1) {
//                    offsetLocalHdr = fileHeader.getZip64ExtendedInfo().getOffsLocalHeaderRelative();
//                }
//
//                fileHeader.setOffsLocalFileHeader(offsetLocalHdr - (offs - offsetLocalFileHeader) - 1);
                }

                prv = removeEntries.contains(header.getFileName()) ? null : header;
                skip = header.getOffsLocalFileHeader() - offsIn;
            }

            if (prv != null) {
                long curOffs = offsOut;
                long length = zipModel.getOffsCentralDirectory() - prv.getOffsLocalFileHeader();
                offsOut += IOUtils.copyLarge(in, out, skip, length);
                fileHeaders.add(prv);
                prv.setOffsLocalFileHeader(curOffs);
            }
        }

        zipModel.setFileHeaders(fileHeaders);
        zipModel.getEndCentralDirectory().setOffsCentralDirectory(offsOut);
    }

    private void restoreFileName(Path tmpZipFileName) {
        try {
            if (tmpZipFileName == null)
                return;
            if (Files.deleteIfExists(zipModel.getZipFile()))
                Files.move(tmpZipFileName, zipModel.getZipFile());
            else
                throw new ZipException("cannot delete old zip file");
        } catch(IOException e) {
            throw new ZipException(e);
        }
    }
}