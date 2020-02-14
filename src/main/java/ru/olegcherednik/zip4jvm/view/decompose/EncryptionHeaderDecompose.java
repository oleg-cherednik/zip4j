package ru.olegcherednik.zip4jvm.view.decompose;

import lombok.RequiredArgsConstructor;
import ru.olegcherednik.zip4jvm.model.Encryption;
import ru.olegcherednik.zip4jvm.model.ZipModel;
import ru.olegcherednik.zip4jvm.model.block.crypto.AesEncryptionHeaderBlock;
import ru.olegcherednik.zip4jvm.model.block.crypto.EncryptionHeaderBlock;
import ru.olegcherednik.zip4jvm.model.block.crypto.PkwareEncryptionHeaderBlock;
import ru.olegcherednik.zip4jvm.model.settings.ZipInfoSettings;
import ru.olegcherednik.zip4jvm.view.crypto.EncryptionHeaderView;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * @author Oleg Cherednik
 * @since 09.12.2019
 */
@RequiredArgsConstructor
public final class EncryptionHeaderDecompose implements Decompose {

    private final ZipModel zipModel;
    private final ZipInfoSettings settings;
    private final Encryption encryption;
    private final EncryptionHeaderBlock encryptionHeaderBlock;
    private final long pos;

    @Override
    public boolean printTextInfo(PrintStream out, boolean emptyLine) {
        if (encryptionHeaderBlock != null)
            return encryptionHeaderView().print(out, emptyLine);

        return emptyLine;
    }

    @Override
    public void decompose(Path dir) throws IOException {
        if (encryptionHeaderBlock == null)
            return;

        Path subDir = Files.createDirectories(dir.resolve("encryption"));

        // TODO probably same with block reader
        if (encryption.isAes()) {
            AesEncryptionHeaderBlock block = (AesEncryptionHeaderBlock)encryptionHeaderBlock;
            Utils.print(subDir.resolve("aes_encryption_header.txt"), out -> encryptionHeaderView().print(out));

            Utils.copyLarge(zipModel, subDir.resolve("aes_salt.data"), block.getSalt());
            Utils.copyLarge(zipModel, subDir.resolve("aes_password_checksum.data"), block.getPasswordChecksum());
            Utils.copyLarge(zipModel, subDir.resolve("aes_mac.data"), block.getMac());
        } else if (encryption == Encryption.PKWARE) {
            PkwareEncryptionHeaderBlock block = (PkwareEncryptionHeaderBlock)encryptionHeaderBlock;
            Utils.print(subDir.resolve("pkware_encryption_header.txt"), out -> encryptionHeaderView().print(out));
            Utils.copyLarge(zipModel, subDir.resolve("pkware_encryption_header.data"), block);
        } else {
            // TODO print unknown header
        }
    }

    private EncryptionHeaderView encryptionHeaderView() {
        int offs = settings.getOffs();
        int columnWidth = settings.getColumnWidth();
        long totalDisks = zipModel.getTotalDisks();
        return new EncryptionHeaderView(encryptionHeaderBlock, pos, offs, columnWidth, totalDisks);
    }
}
