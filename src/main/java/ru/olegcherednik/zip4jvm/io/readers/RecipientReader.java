package ru.olegcherednik.zip4jvm.io.readers;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.crypto.strong.DecryptionInfo;
import ru.olegcherednik.zip4jvm.io.in.DataInput;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Oleg Cherednik
 * @since 05.01.2020
 */
@RequiredArgsConstructor
public final class RecipientReader implements Reader<List<DecryptionInfo.Recipient>> {

    private final long total;
    private final int hashSize;

    @Override
    public List<DecryptionInfo.Recipient> read(DataInput in) throws IOException {
        List<DecryptionInfo.Recipient> recipients = new LinkedList<>();

        for (int i = 0; i < total; i++) {
            DecryptionInfo.Recipient recipient = new DecryptionInfo.Recipient();

            recipient.setSize(in.readWord());
            recipient.setHash(in.readBytes(hashSize));
            recipient.setSimpleKeyBlob(in.readBytes(recipient.getSize() - hashSize));

            recipients.add(recipient);
        }

        return recipients;
    }
}
