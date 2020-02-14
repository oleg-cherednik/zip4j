package ru.olegcherednik.zip4jvm.io.writers;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.io.out.data.DataOutput;
import ru.olegcherednik.zip4jvm.model.Charsets;
import ru.olegcherednik.zip4jvm.model.EndCentralDirectory;
import ru.olegcherednik.zip4jvm.utils.function.Writer;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 10.04.2019
 */
@RequiredArgsConstructor
final class EndCentralDirectoryWriter implements Writer {

    private final EndCentralDirectory endCentralDirectory;

    @Override
    public void write(DataOutput out) throws IOException {
        byte[] comment = endCentralDirectory.getComment(Charsets.UTF_8);

        out.writeDwordSignature(EndCentralDirectory.SIGNATURE);
        out.writeWord(endCentralDirectory.getTotalDisks());
        out.writeWord(endCentralDirectory.getMainDisk());
        out.writeWord(endCentralDirectory.getDiskEntries());
        out.writeWord(endCentralDirectory.getTotalEntries());
        out.writeDword(endCentralDirectory.getCentralDirectorySize());
        out.writeDword(endCentralDirectory.getCentralDirectoryOffs());
        out.writeWord(comment.length);
        out.writeBytes(comment);
    }

}
