package ru.olegcherednik.zip4jvm.io.in.file;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang.math.NumberUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * 7-Zip has not standard split algorithm. It creates the whole zip file first and then split it with required part size. It has following naming
 * convention:
 * <pre>
 * filename.zip.001
 * filename.zip.002
 * filename.zip.003
 * </pre>
 * According to the zip specification, this is not a split archive.
 *
 * @author Oleg Cherednik
 * @since 20.01.2020
 */
@Getter
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
final class SevenZipSplitSrcFile extends SrcFile {

    private final Path path;
    private final List<Item> items;
    private final long length;

    static SevenZipSplitSrcFile create(Path file) {
        String fileName = file.getFileName().toString();
        String ext = FilenameUtils.getExtension(fileName);
        Path parent = file.getParent();

        if (!"zip".equalsIgnoreCase(ext) && NumberUtils.isDigits(ext))
            fileName = FilenameUtils.getBaseName(fileName);
        if (!Files.exists(parent.resolve(fileName + ".001")))
            return null;

        long offs = 0;
        List<Item> items = new LinkedList<>();

        for (int i = 0; ; i++) {
            Path path = parent.resolve(String.format("%s.%03d", fileName, i + 1));

            if (!Files.exists(path))
                break;

            long length = length(path);
            items.add(Item.builder().pos(i).file(path).offs(offs).length(length).build());
            offs += length;
        }

        return new SevenZipSplitSrcFile(parent.resolve(fileName), Collections.unmodifiableList(items), offs);
    }

    private static long length(Path file) {
        try {
            return Files.size(file);
        } catch(IOException ignore) {
            return 0;
        }
    }

    public boolean isLast(Item item) {
        return item == null || items.size() < item.getPos();
    }

    public Item getDisk(int disk) {
        return items.size() <= disk ? null : items.get(disk);
    }

    @Override
    public DataInputFile dataInputFile() throws IOException {
        return new LittleEndianSevenZipReadFile(this);
    }

    @Override
    public boolean isSplit() {
        return false;
    }

    @Override
    public String toString() {
        return String.format("%s (%d)", path.toString(), items.size());
    }
}
