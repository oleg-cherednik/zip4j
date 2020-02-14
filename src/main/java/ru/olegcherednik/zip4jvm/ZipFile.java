/*
 * Copyright © 2019 Cherednik Oleg
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
package ru.olegcherednik.zip4jvm;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import ru.olegcherednik.zip4jvm.engine.InfoEngine;
import ru.olegcherednik.zip4jvm.engine.UnzipEngine;
import ru.olegcherednik.zip4jvm.engine.ZipEngine;
import ru.olegcherednik.zip4jvm.exception.EntryNotFoundException;
import ru.olegcherednik.zip4jvm.io.in.file.SrcFile;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;
import ru.olegcherednik.zip4jvm.model.ExternalFileAttributes;
import ru.olegcherednik.zip4jvm.model.settings.UnzipSettings;
import ru.olegcherednik.zip4jvm.model.settings.ZipInfoSettings;
import ru.olegcherednik.zip4jvm.model.settings.ZipSettings;
import ru.olegcherednik.zip4jvm.utils.EmptyInputStream;
import ru.olegcherednik.zip4jvm.utils.EmptyInputStreamSupplier;
import ru.olegcherednik.zip4jvm.utils.PathUtils;
import ru.olegcherednik.zip4jvm.utils.ZipUtils;
import ru.olegcherednik.zip4jvm.utils.function.InputStreamSupplier;

import java.io.Closeable;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static ru.olegcherednik.zip4jvm.model.ExternalFileAttributes.PROP_OS_NAME;

/**
 * @author Oleg Cherednik
 * @since 01.09.2019
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ZipFile {

    static Writer writer(Path zip, ZipSettings settings) throws IOException {
        return new ZipEngine(zip, settings);
    }

    static Reader reader(SrcFile srcFile, UnzipSettings settings) throws IOException {
        return new UnzipEngine(srcFile, settings);
    }

    static Info info(SrcFile srcFile, ZipInfoSettings settings) throws IOException {
        return new InfoEngine(srcFile, settings);
    }

    @Getter
    public static final class Entry {

        @Getter(AccessLevel.NONE)
        private final InputStreamSupplier inputStreamSupplier;
        /** Normalized file name without directory marker {@literal /} */
        private final String fileName;
        private final long lastModifiedTime;
        private final long uncompressedSize;
        private final ExternalFileAttributes externalFileAttributes;
        private final boolean regularFile;

        public static Entry of(Path path, String fileName) throws IOException {
            ZipFile.Entry.Builder builder = builder()
                    .lastModifiedTime(Files.getLastModifiedTime(path).toMillis())
                    .externalFileAttributes(ExternalFileAttributes.build(PROP_OS_NAME).readFrom(path));

            if (Files.isRegularFile(path)) {
                builder.fileName(fileName);
                builder.uncompressedSize(Files.size(path));
                builder.inputStreamSupplier(() -> new FileInputStream(path.toFile()));
            } else
                builder.directoryName(fileName);

            return builder.build();
        }

        public static Entry.Builder builder() {
            return new Entry.Builder();
        }

        private Entry(Entry.Builder builder) {
            fileName = ZipUtils.normalizeFileName(builder.fileName);
            inputStreamSupplier = builder.regularFile ? builder.inputStreamSupplier : () -> EmptyInputStream.INSTANCE;
            lastModifiedTime = builder.lastModifiedTime;
            uncompressedSize = builder.uncompressedSize;
            externalFileAttributes = builder.externalFileAttributes;
            regularFile = builder.regularFile;
        }

        public InputStream getInputStream() throws IOException {
            return inputStreamSupplier.get();
        }

        @NoArgsConstructor(access = AccessLevel.PRIVATE)
        public static final class Builder {

            private InputStreamSupplier inputStreamSupplier = EmptyInputStreamSupplier.INSTANCE;
            private String fileName;
            private long lastModifiedTime = System.currentTimeMillis();
            private long uncompressedSize;
            private ExternalFileAttributes externalFileAttributes = ExternalFileAttributes.NULL;
            private boolean regularFile = true;

            public Entry build() {
                return new Entry(this);
            }

            public Entry.Builder inputStreamSupplier(InputStreamSupplier inputStreamSupplier) {
                this.inputStreamSupplier = Optional.ofNullable(inputStreamSupplier).orElse(EmptyInputStreamSupplier.INSTANCE);
                return this;
            }

            public Entry.Builder fileName(String fileName) {
                this.fileName = ZipUtils.getFileNameNoDirectoryMarker(fileName);
                regularFile = true;
                return this;
            }

            public Entry.Builder directoryName(String fileName) {
                this.fileName = ZipUtils.getFileNameNoDirectoryMarker(fileName);
                regularFile = false;
                return this;
            }

            public Entry.Builder lastModifiedTime(long lastModifiedTime) {
                this.lastModifiedTime = lastModifiedTime;
                return this;
            }

            public Entry.Builder uncompressedSize(long uncompressedSize) {
                this.uncompressedSize = uncompressedSize;
                return this;
            }

            public Entry.Builder externalFileAttributes(ExternalFileAttributes externalFileAttributes) {
                this.externalFileAttributes = externalFileAttributes;
                return this;
            }
        }
    }

    public interface Writer extends Closeable {

        default void add(Path path) throws IOException {
            for (Map.Entry<Path, String> entry : PathUtils.getRelativeContent(path).entrySet())
                add(Entry.of(entry.getKey(), entry.getValue()));
        }

        void add(Entry entry);

        void removeEntryByName(String entryName) throws EntryNotFoundException;

        void removeEntryByNamePrefix(String entryNamePrefix) throws EntryNotFoundException;

        void copy(Path zip) throws IOException;

        void setComment(String comment);
    }

    public interface Reader extends Iterable<ZipFile.Entry> {

        void extract(Path destDir) throws IOException;

        void extract(Path destDir, String fileName) throws IOException;

        ZipFile.Entry extract(String fileName) throws IOException;

        default Stream<Entry> stream() {
            return StreamSupport.stream(spliterator(), false);
        }

        String getComment();

        boolean isSplit();

        boolean isZip64();
    }

    public interface Info {

        void printTextInfo(PrintStream out) throws IOException;

        void decompose(Path dir) throws IOException;

        CentralDirectory.FileHeader getFileHeader(String entryName) throws IOException;
    }

}
