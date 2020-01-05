package ru.olegcherednik.zip4jvm.io.readers;

import ru.olegcherednik.zip4jvm.crypto.strong.DecryptionInfo;
import ru.olegcherednik.zip4jvm.crypto.strong.EncryptionAlgorithm;
import ru.olegcherednik.zip4jvm.io.in.DataInput;
import ru.olegcherednik.zip4jvm.utils.function.Reader;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 05.01.2020
 */
public final class DecryptionInfoReader implements Reader<DecryptionInfo> {

    @Override
    public DecryptionInfo read(DataInput in) throws IOException {
        DecryptionInfo info = new DecryptionInfo();

        info.setVersion(in.readWord());
        info.setEncryptionAlgorithm(EncryptionAlgorithm.parseCode(in.readWord()));
        info.setBitLength(in.readWord());
        info.setFlags(DecryptionInfo.Flags.parseCode(in.readWord()));
        info.setEncryptedRandomDataSize(in.readWord());
        info.setEncryptedRandomData(in.readBytes(info.getEncryptedRandomDataSize()));
        info.setRecipientCount(in.readDword());
        info.setHashAlgorithm(info.getFlags() == DecryptionInfo.Flags.PASSWORD_KEY ? 0x0 : in.readWord());
        info.setHashSize(info.getFlags() == DecryptionInfo.Flags.PASSWORD_KEY ? 0x0 : in.readWord());
        info.setRecipients(new RecipientReader(info.getRecipientCount(), info.getHashSize()).read(in));
        info.setPasswordValidationDataSize(in.readWord());
        info.setPasswordValidationData(in.readBytes(info.getPasswordValidationDataSize() - 4));
        info.setCrc32(in.readDword());
        return info;
    }

}
