package ru.olegcherednik.zip4jvm.engine;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.ZipFile;
import ru.olegcherednik.zip4jvm.exception.EntryNotFoundException;
import ru.olegcherednik.zip4jvm.io.in.file.SrcFile;
import ru.olegcherednik.zip4jvm.io.readers.ZipModelReader;
import ru.olegcherednik.zip4jvm.io.readers.block.BlockModelReader;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;
import ru.olegcherednik.zip4jvm.model.block.BlockModel;
import ru.olegcherednik.zip4jvm.model.settings.ZipInfoSettings;
import ru.olegcherednik.zip4jvm.view.decompose.CentralDirectoryDecompose;
import ru.olegcherednik.zip4jvm.view.decompose.EndCentralDirectoryDecompose;
import ru.olegcherednik.zip4jvm.view.decompose.Zip64Decompose;
import ru.olegcherednik.zip4jvm.view.decompose.ZipEntriesDecompose;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * @author Oleg Cherednik
 * @since 15.11.2019
 */
@RequiredArgsConstructor
public final class InfoEngine implements ZipFile.Info {

    private final SrcFile srcFile;
    private final ZipInfoSettings settings;

    @Override
    public void printTextInfo(PrintStream out) throws IOException {
        BlockModel blockModel = createModel();

        boolean emptyLine = new EndCentralDirectoryDecompose(blockModel, settings).printTextInfo(out, false);
        emptyLine |= new Zip64Decompose(blockModel, settings).printTextInfo(out, emptyLine);
        emptyLine |= new CentralDirectoryDecompose(blockModel, settings).printTextInfo(out, emptyLine);
        new ZipEntriesDecompose(blockModel, settings).printTextInfo(out, emptyLine);
    }

    @Override
    public void decompose(Path dir) throws IOException {
        Files.createDirectories(dir);

        BlockModel blockModel = createModel();

        new EndCentralDirectoryDecompose(blockModel, settings).decompose(dir);
        new Zip64Decompose(blockModel, settings).decompose(dir);
        new CentralDirectoryDecompose(blockModel, settings).decompose(dir);
        new ZipEntriesDecompose(blockModel, settings).decompose(dir);
    }

    @Override
    public CentralDirectory.FileHeader getFileHeader(String entryName) throws IOException {
        ZipModelReader zipModelReader = new ZipModelReader(srcFile, settings.getCustomizeCharset());
        zipModelReader.readCentralData();
        return zipModelReader.getCentralDirectory().getFileHeaders().stream()
                             .filter(fh -> fh.getFileName().equalsIgnoreCase(entryName))
                             .findFirst().orElseThrow(() -> new EntryNotFoundException(entryName));
    }

    private BlockModel createModel() throws IOException {
        BlockModelReader reader = new BlockModelReader(srcFile, settings.getCustomizeCharset());
        return settings.isReadEntries() ? reader.readWithEntries() : reader.read();
    }

}
