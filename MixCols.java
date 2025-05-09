// MixCols.java
public class MixCols {
    // Galois-field multiplication tables
    static final int[] mc2  = new int[256];
    static final int[] mc3  = new int[256];
    static final int[] mc9  = new int[256];
    static final int[] mc11 = new int[256];
    static final int[] mc13 = new int[256];
    static final int[] mc14 = new int[256];

    static {
        // precompute xtime tables for 2× and 3× (and inverses 9,11,13,14) in GF(2^8)
        for (int i = 0; i < 256; i++) {
            int x = i;
            mc2[i]  = xtime(x);
            mc3[i]  = mc2[i] ^ x;
            mc9[i]  = xtime(xtime(xtime(x))) ^ x;
            mc11[i] = mc9[i] ^ mc2[i];
            mc13[i] = mc9[i] ^ xtime(x);
            mc14[i] = mc9[i] ^ xtime(x) ^ x;
        }
    }

    private static int xtime(int b) {
        int v = (b<<1) & 0xFF;
        if ((b & 0x80) != 0) v ^= 0x1B;
        return v;
    }

    /** forward MixColumns on one 32-bit column word */
    public static int mix(int col) {
        int a0 = (col>>>24)&0xFF, a1 = (col>>>16)&0xFF,
                a2 = (col>>> 8)&0xFF, a3 =  col       &0xFF;
        int r0 = mc2[a0] ^ mc3[a1] ^  a2    ^  a3;
        int r1 =  a0    ^ mc2[a1] ^ mc3[a2] ^  a3;
        int r2 =  a0    ^  a1    ^ mc2[a2] ^ mc3[a3];
        int r3 = mc3[a0] ^  a1    ^  a2    ^ mc2[a3];
        return (r0<<24)|(r1<<16)|(r2<<8)|r3;
    }

    /** inverse MixColumns on one 32-bit column word */
    public static int invMix(int col) {
        int a0 = (col>>>24)&0xFF, a1 = (col>>>16)&0xFF,
                a2 = (col>>> 8)&0xFF, a3 =  col       &0xFF;
        int r0 = mc14[a0] ^ mc11[a1] ^ mc13[a2] ^ mc9[a3];
        int r1 = mc9[a0]  ^ mc14[a1] ^ mc11[a2] ^ mc13[a3];
        int r2 = mc13[a0] ^ mc9[a1]  ^ mc14[a2] ^ mc11[a3];
        int r3 = mc11[a0] ^ mc13[a1] ^ mc9[a2]  ^ mc14[a3];
        return (r0<<24)|(r1<<16)|(r2<<8)|r3;
    }
}
