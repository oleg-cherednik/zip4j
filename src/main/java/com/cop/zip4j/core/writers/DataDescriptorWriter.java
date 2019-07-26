package com.cop.zip4j.core.writers;

import com.cop.zip4j.io.SplitOutputStream;
import com.cop.zip4j.model.DataDescriptor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.io.IOException;

/**
 * @author Oleg Cherednik
 * @since 25.07.2019
 */
@RequiredArgsConstructor
public final class DataDescriptorWriter {

    @NonNull
    private final DataDescriptor dataDescriptor;

    public void write(@NonNull SplitOutputStream out) throws IOException {
        out.writeDword((int)dataDescriptor.getCrc32());
        out.writeDword(dataDescriptor.getCompressedSize());
        out.writeDword(dataDescriptor.getUncompressedSize());
    }

}
