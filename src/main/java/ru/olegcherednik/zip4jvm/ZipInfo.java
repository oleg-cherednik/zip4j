package ru.olegcherednik.zip4jvm;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.io.in.file.SrcFile;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;
import ru.olegcherednik.zip4jvm.model.settings.ZipInfoSettings;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.Optional;

import static ru.olegcherednik.zip4jvm.utils.ValidationUtils.requireNotNull;

/**
 * @author Oleg Cherednik
 * @since 11.10.2019
 */
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public final class ZipInfo {

    private final SrcFile srcFile;
    private ZipInfoSettings settings = ZipInfoSettings.DEFAULT;

    public static ZipInfo zip(Path zip) {
        requireNotNull(zip, "ZipInfo.zip");
        return new ZipInfo(SrcFile.of(zip));
    }

    public ZipInfo settings(ZipInfoSettings settings) {
        this.settings = Optional.ofNullable(settings).orElse(ZipInfoSettings.DEFAULT);
        return this;
    }

    public void printShortInfo() throws IOException {
        printShortInfo(System.out);
    }

    public void printShortInfo(PrintStream out) throws IOException {
        ZipFile.info(srcFile, settings).printTextInfo(out);
    }

    public void decompose(Path destDir) throws IOException {
        ZipFile.info(srcFile, settings).decompose(destDir);
    }

    public CentralDirectory.FileHeader getFileHeader(String entryName) throws IOException {
        return ZipFile.info(srcFile, settings).getFileHeader(entryName);
    }

}
