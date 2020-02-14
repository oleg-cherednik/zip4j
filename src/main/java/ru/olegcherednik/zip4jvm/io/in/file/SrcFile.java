package ru.olegcherednik.zip4jvm.io.in.file;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.IOException;
import java.nio.file.Path;

/**
 * @author Oleg Cherednik
 * @since 20.01.2020
 */
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class SrcFile {

    public static SrcFile of(Path file) {
        SrcFile srcFile = SevenZipSplitSrcFile.create(file);
        return srcFile == null ? new StandardSrcFile(file) : srcFile;
    }

    public abstract Path getPath();

    public abstract DataInputFile dataInputFile() throws IOException;

    public abstract boolean isSplit() throws IOException;

    @Getter
    @Builder
    public static final class Item {

        private final int pos;
        private final Path file;
        private final long offs;
        private final long length;

        @Override
        public String toString() {
            return String.format("%s (offs: %s)", file, offs);
        }
    }

}
