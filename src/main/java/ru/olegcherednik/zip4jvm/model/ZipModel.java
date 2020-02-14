package ru.olegcherednik.zip4jvm.model;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang.StringUtils;
import ru.olegcherednik.zip4jvm.exception.EntryNotFoundException;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.io.in.data.SingleZipInputStream;
import ru.olegcherednik.zip4jvm.io.in.data.SplitZipInputStream;
import ru.olegcherednik.zip4jvm.io.in.file.SrcFile;
import ru.olegcherednik.zip4jvm.model.entry.ZipEntry;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static ru.olegcherednik.zip4jvm.utils.ValidationUtils.requireMaxSizeComment;

/**
 * @author Oleg Cherednik
 * @since 10.03.2019
 */
@Getter
@Setter
@RequiredArgsConstructor
public final class ZipModel {

    public static final int NO_SPLIT = -1;
    public static final int MIN_SPLIT_SIZE = 64 * 1024; // 64Kb

    public static final int MAX_TOTAL_ENTRIES = Zip64.LIMIT_WORD;
    public static final long MAX_ENTRY_SIZE = Zip64.LIMIT_DWORD;
    public static final long MAX_CENTRAL_DIRECTORY_OFFS = Zip64.LIMIT_DWORD;
    public static final long MAX_LOCAL_FILE_HEADER_OFFS = Zip64.LIMIT_DWORD;
    public static final int MAX_TOTAL_DISKS = Zip64.LIMIT_WORD;
    public static final int MAX_COMMENT_SIZE = Zip64.LIMIT_WORD;

    private final SrcFile srcFile;
    private long splitSize = NO_SPLIT;

    private String comment;
    private long totalDisks;
    private long mainDisk;
    private long centralDirectoryOffs;
    private long centralDirectorySize;

    /**
     * {@literal true} only if section {@link Zip64} exists. In other words, do set this to {@code true}, to write zip archive
     * in ZIP64 format.
     */
    private boolean zip64;

    @Getter(AccessLevel.NONE)
    private final Map<String, ZipEntry> fileNameEntry = new LinkedHashMap<>();

    public void setComment(String comment) {
        requireMaxSizeComment(comment, MAX_COMMENT_SIZE);
        this.comment = StringUtils.isEmpty(comment) ? null : comment;
    }

    public boolean isSplit() {
        return splitSize > 0 || totalDisks > 0;
    }

    public boolean isEmpty() {
        return fileNameEntry.isEmpty();
    }

    public int getTotalEntries() {
        return fileNameEntry.size();
    }

    public void addEntry(ZipEntry zipEntry) {
        fileNameEntry.put(zipEntry.getFileName(), zipEntry);
    }

    public Collection<ZipEntry> getZipEntries() {
        return isEmpty() ? Collections.emptyList() : Collections.unmodifiableCollection(fileNameEntry.values());
    }

    public ZipEntry getZipEntryByFileName(String fileName) {
        if (!fileNameEntry.containsKey(fileName))
            throw new EntryNotFoundException(fileName);

        return fileNameEntry.get(fileName);
    }

    public boolean hasEntry(String fileName) {
        return fileNameEntry.containsKey(fileName);
    }

    public Set<String> getEntryNames() {
        return isEmpty() ? Collections.emptySet() : Collections.unmodifiableSet(fileNameEntry.keySet());
    }

    public Path getDiskFile(long disk) {
        return disk >= totalDisks ? srcFile.getPath() : getDiskFile(srcFile.getPath(), disk + 1);
    }

    public static Path getDiskFile(Path file, long disk) {
        return file.getParent().resolve(String.format("%s.z%02d", FilenameUtils.getBaseName(file.toString()), disk));
    }

    public DataInput createDataInput(String fileName) throws IOException {
        return isSplit() ? new SplitZipInputStream(this, getZipEntryByFileName(fileName).getDisk()) : new SingleZipInputStream(this);
    }

    public DataInput createDataInput() throws IOException {
        return isSplit() ? new SplitZipInputStream(this, 0) : new SingleZipInputStream(this);
    }

}
