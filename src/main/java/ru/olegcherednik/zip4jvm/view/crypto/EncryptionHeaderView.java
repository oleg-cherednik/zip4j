package ru.olegcherednik.zip4jvm.view.crypto;

import ru.olegcherednik.zip4jvm.model.block.crypto.AesEncryptionHeaderBlock;
import ru.olegcherednik.zip4jvm.model.block.crypto.EncryptionHeaderBlock;
import ru.olegcherednik.zip4jvm.model.block.crypto.PkwareEncryptionHeaderBlock;
import ru.olegcherednik.zip4jvm.view.BaseView;

import java.io.PrintStream;

import static ru.olegcherednik.zip4jvm.utils.ValidationUtils.requireNotNull;

/**
 * @author Oleg Cherednik
 * @since 24.10.2019
 */
public final class EncryptionHeaderView extends BaseView {

    private final EncryptionHeaderBlock block;
    private final long pos;

    public EncryptionHeaderView(EncryptionHeaderBlock block, long pos, int offs, int columnWidth) {
        super(offs, columnWidth);
        this.block = requireNotNull(block, "EncryptionHeaderView.centralDirectory");
        this.pos = pos;
    }

    @Override
    public boolean print(PrintStream out) {
        if (block instanceof AesEncryptionHeaderBlock)
            createView((AesEncryptionHeaderBlock)block).print(out);
        else if (block instanceof PkwareEncryptionHeaderBlock)
            createView((PkwareEncryptionHeaderBlock)block).print(out);
        // TODO add for unknown encryption header

        return true;
    }

    public BlockAesEncryptionHeaderView createView(AesEncryptionHeaderBlock block) {
        return new BlockAesEncryptionHeaderView(block, pos, offs, columnWidth);
    }

    public PkwareEncryptionHeaderView createView(PkwareEncryptionHeaderBlock block) {
        return new PkwareEncryptionHeaderView(block, pos, offs, columnWidth);
    }
}
