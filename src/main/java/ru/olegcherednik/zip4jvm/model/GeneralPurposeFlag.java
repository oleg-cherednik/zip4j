package ru.olegcherednik.zip4jvm.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import ru.olegcherednik.zip4jvm.utils.BitUtils;

import java.nio.charset.Charset;

import static ru.olegcherednik.zip4jvm.utils.BitUtils.BIT0;
import static ru.olegcherednik.zip4jvm.utils.BitUtils.BIT1;
import static ru.olegcherednik.zip4jvm.utils.BitUtils.BIT11;
import static ru.olegcherednik.zip4jvm.utils.BitUtils.BIT2;
import static ru.olegcherednik.zip4jvm.utils.BitUtils.BIT3;
import static ru.olegcherednik.zip4jvm.utils.BitUtils.BIT6;

/**
 * see 4.4.4
 *
 * @author Oleg Cherednik
 * @since 12.03.2019
 */
@Getter
@Setter
@NoArgsConstructor
public class GeneralPurposeFlag {

    private boolean encrypted;
    private CompressionLevel compressionLevel = CompressionLevel.NORMAL;
    private SlidingDictionarySize slidingDictionarySize = SlidingDictionarySize.SD_4K;
    private ShannonFanoTreesNumber shannonFanoTreesNumber = ShannonFanoTreesNumber.TWO;
    private boolean lzmaEosMarker;
    /** {@link DataDescriptor} */
    private boolean dataDescriptorAvailable;
    private boolean strongEncryption;
    private boolean utf8;

    public GeneralPurposeFlag(int data) {
        read(data);
    }

    public void read(int data) {
        encrypted = BitUtils.isBitSet(data, BIT0);
        compressionLevel = getCompressionLevel(data);
        slidingDictionarySize = getSlidingDictionarySize(data);
        shannonFanoTreesNumber = getShannonFanoTreesNumber(data);
        lzmaEosMarker = BitUtils.isBitSet(data, BIT1);
        dataDescriptorAvailable = BitUtils.isBitSet(data, BIT3);
        strongEncryption = BitUtils.isBitSet(data, BIT6);
        utf8 = BitUtils.isBitSet(data, BIT11);
    }

    private static CompressionLevel getCompressionLevel(int data) {
        if (BitUtils.isBitSet(data, BIT1 | BIT2))
            return CompressionLevel.SUPER_FAST;
        if (BitUtils.isBitSet(data, BIT2))
            return CompressionLevel.FAST;
        return BitUtils.isBitSet(data, BIT1) ? CompressionLevel.MAXIMUM : CompressionLevel.NORMAL;
    }

    private static SlidingDictionarySize getSlidingDictionarySize(int data) {
        return BitUtils.isBitSet(data, BIT1) ? SlidingDictionarySize.SD_8K : SlidingDictionarySize.SD_4K;
    }

    private static ShannonFanoTreesNumber getShannonFanoTreesNumber(int data) {
        return BitUtils.isBitSet(data, BIT2) ? ShannonFanoTreesNumber.THREE : ShannonFanoTreesNumber.TWO;
    }

    public int getAsInt(CompressionMethod compressionMethod) {
        int data = BitUtils.updateBits(0, BIT0, encrypted);
        data |= getCompressionMethodBits(compressionMethod);
        data = BitUtils.updateBits(data, BIT3, dataDescriptorAvailable);
        data = BitUtils.updateBits(data, BIT6, strongEncryption);
        data = BitUtils.updateBits(data, BIT11, utf8);
        return data;
    }

    private int getCompressionMethodBits(CompressionMethod compressionMethod) {
        if (compressionMethod == CompressionMethod.FILE_IMPLODED)
            return getImplodedBits();
        if (compressionMethod == CompressionMethod.DEFLATE || compressionMethod == CompressionMethod.ENHANCED_DEFLATE)
            return getDeflateBits();
        if (compressionMethod == CompressionMethod.LZMA)
            return getLzmaBits();
        return 0;
    }

    private int getImplodedBits() {
        int res = 0;

        if (slidingDictionarySize == SlidingDictionarySize.SD_8K)
            res |= BIT1;
        if (shannonFanoTreesNumber == ShannonFanoTreesNumber.THREE)
            res |= BIT2;

        return res;
    }

    private int getDeflateBits() {
        if (compressionLevel == CompressionLevel.MAXIMUM)
            return BIT1;
        if (compressionLevel == CompressionLevel.FAST)
            return BIT2;
        if (compressionLevel == CompressionLevel.SUPER_FAST)
            return BIT1 | BIT2;
        return 0x0;
    }

    private int getLzmaBits() {
        return lzmaEosMarker ? BIT1 : 0;
    }

    public Charset getCharset() {
        return utf8 ? Charsets.UTF_8 : Charsets.IBM437;
    }
}
