package ru.olegcherednik.zip4jvm.io.readers.block;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.io.in.data.DataInput;
import ru.olegcherednik.zip4jvm.io.readers.DigitalSignatureReader;
import ru.olegcherednik.zip4jvm.model.CentralDirectory;
import ru.olegcherednik.zip4jvm.model.block.Block;
import ru.olegcherednik.zip4jvm.model.block.CentralDirectoryBlock;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 20.10.2019
 */
@RequiredArgsConstructor
public class BlockDigitalSignatureReader extends DigitalSignatureReader {

    private final CentralDirectoryBlock centralDirectoryBlock;

    @Override
    protected CentralDirectory.DigitalSignature readDigitalSignature(DataInput in) throws IOException {
        Block block = new Block();
        CentralDirectory.DigitalSignature digitalSignature = block.calc(in, () -> super.readDigitalSignature(in));
        centralDirectoryBlock.setDigitalSignature(block);
        return digitalSignature;
    }
}
