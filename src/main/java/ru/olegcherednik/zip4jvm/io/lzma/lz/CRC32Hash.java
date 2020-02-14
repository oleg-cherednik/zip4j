package ru.olegcherednik.zip4jvm.io.lzma.lz;

/**
 * Provides a CRC32 table using the polynomial from IEEE 802.3
 *
 * @author Oleg Cherednik
 * @since 14.02.2020
 */
@SuppressWarnings("NewClassNamingConvention")
final class CRC32Hash {

    private static final int[] CRC_TABLE = createTable();

    private final HashData two = new HashData(1024);
    private final HashData three = new HashData(65536);
    private final HashData four;

    public CRC32Hash(int dictionarySize) {
        four = new HashData(getHash4Size(dictionarySize));
    }

    public void calcHashes(byte[] buf, int offs) {
        int tmp = CRC_TABLE[buf[offs] & 0xFF] ^ (buf[offs + 1] & 0xFF);
        two.setValue(tmp);
        three.setValue(tmp ^= (buf[offs + 2] & 0xFF) << 8);
        four.setValue(tmp ^ CRC_TABLE[buf[offs + 3] & 0xFF] << 5);
    }

    public int getHash2Pos() {
        return two.getPos();
    }

    public int getHash3Pos() {
        return three.getPos();
    }

    public int getHash4Pos() {
        return four.getPos();
    }

    public void updateTables(int pos) {
        two.update(pos);
        three.update(pos);
        four.update(pos);
    }

    public void normalize(int offs) {
        two.normalize(offs);
        three.normalize(offs);
        four.normalize(offs);
    }

    private static int[] createTable() {
        int[] arr = new int[256];

        for (int i = 0, r = i; i < arr.length; i++, r = i) {
            for (int j = 0; j < 8; j++)
                r = (r & 1) != 0 ? (r >>> 1) ^ 0xEDB88320 : r >>> 1;

            arr[i] = r;
        }

        return arr;
    }

    @SuppressWarnings("NewMethodNamingConvention")
    private static int getHash4Size(int dictionarySize) {
        int h = dictionarySize - 1;
        h |= h >>> 1;
        h |= h >>> 2;
        h |= h >>> 4;
        h |= h >>> 8;
        h >>>= 1;
        h |= 0xFFFF;

        if (h > (1 << 24))
            h >>>= 1;

        return h + 1;
    }

    private static final class HashData {

        private final int[] table;
        private int value;

        public HashData(int size) {
            table = new int[size];
        }

        public void update(int value) {
            table[this.value] = value;
        }

        public int getPos() {
            return table[value];
        }

        public void setValue(int prv) {
            value = prv & (table.length - 1);
        }

        public void normalize(int offs) {
            LzEncoder.normalize(table, table.length, offs);
        }

    }
}
