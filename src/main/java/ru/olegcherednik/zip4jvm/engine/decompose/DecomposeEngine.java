package ru.olegcherednik.zip4jvm.engine.decompose;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.io.readers.block.BlockModelReader;
import ru.olegcherednik.zip4jvm.model.block.BlockModel;
import ru.olegcherednik.zip4jvm.model.settings.ZipInfoSettings;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * @author Oleg Cherednik
 * @since 15.11.2019
 */
@RequiredArgsConstructor
public final class DecomposeEngine {

    private final Path zip;
    private final ZipInfoSettings settings;

    public void printTextInfo(PrintStream out) throws IOException {
        BlockModel blockModel = createModel();

        boolean emptyLine = new EndCentralDirectoryDecompose(blockModel, settings).printTextInfo(out, false);
        emptyLine |= new Zip64Decompose(blockModel, settings).printTextInfo(out, emptyLine);
        emptyLine |= new CentralDirectoryDecompose(blockModel, settings).printTextInfo(out, emptyLine);
        new ZipEntriesDecompose(blockModel, settings).printTextInfo(out, emptyLine);
    }

    public void decompose(Path dir) throws IOException {
        Files.createDirectories(dir);

        BlockModel blockModel = createModel();

        new EndCentralDirectoryDecompose(blockModel, settings).decompose(dir);
        new Zip64Decompose(blockModel, settings).decompose(dir);
        new CentralDirectoryDecompose(blockModel, settings).decompose(dir);
        new ZipEntriesDecompose(blockModel, settings).decompose(dir);
    }

    private BlockModel createModel() throws IOException {
        BlockModelReader reader = new BlockModelReader(zip, settings.getCustomizeCharset());
        return settings.isReadEntries() ? reader.readWithEntries() : reader.read();
    }

}
