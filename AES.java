// AES.java
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;

public class AES {
    private static final int Nb = 4;
    private int Nk;              // key length in words
    private int Nr;              // number of rounds
    private int[][][] roundKey;  // roundKey[round][row][col]
    private boolean debug = false;

    private static final HashMap<Integer,Integer> RC = new HashMap<>();
    static {
        RC.put(1, 0x01);  RC.put(2, 0x02);  RC.put(3, 0x04);  RC.put(4, 0x08);
        RC.put(5, 0x10);  RC.put(6, 0x20);  RC.put(7, 0x40);  RC.put(8, 0x80);
        RC.put(9, 0x1B);  RC.put(10,0x36);
    }

    public AES(String key) {
        this(key, false);
    }
    public AES(String key, boolean debug) {
        this.debug = debug;
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        this.Nk = keyBytes.length / 4;
        this.Nr = Nk + 6;
        this.roundKey = new int[Nr+1][4][Nb];
        keyExpansion(keyBytes);
    }

    public String encrypt(String plaintext, boolean cbcMode) {
        int blocks = (plaintext.getBytes(StandardCharsets.UTF_8).length + 15) / 16;
        byte[] iv = new byte[16];  // zero IV
        StringBuilder out = new StringBuilder();
        for (int b = 0; b < blocks; b++) {
            // build state matrix
            byte[] block = new byte[16];
            byte[] ptBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            for (int i = 0; i < 16; i++) {
                block[i] = (b*16 + i < ptBytes.length) ? ptBytes[b*16 + i] : 0;
                if (cbcMode) block[i] ^= iv[i];
            }
            int[][] state = new int[4][Nb];
            for (int i=0;i<16;i++) state[i%4][i/4] = block[i] & 0xFF;

            cipher(state, true);

            byte[] ct = new byte[16];
            for (int i=0;i<16;i++) {
                ct[i] = (byte) state[i%4][i/4];
            }
            iv = ct;  // CBC chaining
            out.append(bytesToHex(ct));
        }
        return out.toString();
    }

    public String decrypt(String ciphertext, boolean cbcMode) {
        int blocks = ciphertext.length()/32;
        byte[] prev = new byte[16];
        StringBuilder out = new StringBuilder();
        for (int b=0; b<blocks; b++) {
            byte[] ct = hexToBytes(ciphertext.substring(b*32, b*32+32));
            int[][] state = new int[4][Nb];
            for (int i=0;i<16;i++) state[i%4][i/4] = ct[i]&0xFF;

            cipher(state, false);

            byte[] pt = new byte[16];
            for (int i=0;i<16;i++) {
                byte v = (byte) state[i%4][i/4];
                pt[i] = cbcMode ? (byte)(v ^ prev[i]) : v;
            }
            prev = ct;
            out.append(new String(pt, StandardCharsets.UTF_8));
        }
        return out.toString();
    }

    public void cipher(int[][] state, boolean encryptMode) {
        if (encryptMode) {
            addRoundKey(state, roundKey[0]);
            if (debug) printState("Add Round Key", state);
            for (int round = 1; round < Nr; round++) {
                subBytes(state, true);    if (debug) printState("Sub Bytes", state);
                shiftRows(state, true);   if (debug) printState("Shift Rows", state);
                mixColumns(state, true);  if (debug) printState("Mix Columns", state);
                addRoundKey(state, roundKey[round]);
                if (debug) printState("Add Round Key", state);
            }
            subBytes(state, true);    if (debug) printState("Sub Bytes", state);
            shiftRows(state, true);   if (debug) printState("Shift Rows", state);
            addRoundKey(state, roundKey[Nr]);
            if (debug) printState("Add Round Key", state);
        } else {
            addRoundKey(state, roundKey[Nr]);
            if (debug) printState("Add Round Key", state);
            shiftRows(state, false);
            if (debug) printState("Shift Rows", state);
            subBytes(state, false);
            if (debug) printState("Sub Bytes", state);
            for (int round = Nr-1; round > 0; round--) {
                addRoundKey(state, roundKey[round]);
                if (debug) printState("Add Round Key", state);
                mixColumns(state, false);
                if (debug) printState("Inv Mix Columns", state);
                shiftRows(state, false);
                if (debug) printState("Shift Rows", state);
                subBytes(state, false);
                if (debug) printState("Sub Bytes", state);
            }
            addRoundKey(state, roundKey[0]);
            if (debug) printState("Add Round Key", state);
        }
    }

    private void keyExpansion(byte[] key) {
        int totalWords = Nb*(Nr+1);
        int[] w = new int[totalWords];
        // initial key copy
        for (int i=0; i<Nk; i++) {
            w[i] = ((key[4*i]&0xFF)<<24) | ((key[4*i+1]&0xFF)<<16)
                    | ((key[4*i+2]&0xFF)<<8) |  (key[4*i+3]&0xFF);
        }
        // expand
        for (int i=Nk; i<totalWords; i++) {
            int temp = w[i-1];
            if (i % Nk == 0) {
                temp = subWord(rotWord(temp)) ^ (RC.get(i/Nk) << 24);
            } else if (Nk>6 && i%Nk==4) {
                temp = subWord(temp);
            }
            w[i] = w[i-Nk] ^ temp;
        }
        // fill roundKey
        for (int r=0; r<=Nr; r++) {
            for (int c=0; c<Nb; c++) {
                int word = w[r*Nb + c];
                roundKey[r][0][c] = (word >>> 24) & 0xFF;
                roundKey[r][1][c] = (word >>> 16) & 0xFF;
                roundKey[r][2][c] = (word >>>  8) & 0xFF;
                roundKey[r][3][c] =  word         & 0xFF;
            }
        }
    }

    private int subWord(int w) {
        return (SBox.sbox((w>>>24)&0xFF)<<24)
                | (SBox.sbox((w>>>16)&0xFF)<<16)
                | (SBox.sbox((w>>> 8)&0xFF)<< 8)
                |  SBox.sbox( w       &0xFF);
    }
    private int rotWord(int w) {
        return ((w<<8) | (w>>>24)) & 0xFFFFFFFF;
    }

    private void subBytes(int[][] st, boolean mode) {
        for (int r=0;r<4;r++) for (int c=0;c<Nb;c++) {
            st[r][c] = mode
                    ? SBox.sbox(st[r][c])
                    : SBox.invSbox(st[r][c]);
        }
    }
    private void shiftRows(int[][] st, boolean mode) {
        for (int r=1;r<4;r++) {
            int[] tmp = new int[4];
            for (int c=0;c<4;c++) {
                tmp[c] = st[r][ mode ? (c+r)%4 : (c-r+4)%4 ];
            }
            st[r] = tmp;
        }
    }
    public void mixColumns(int[][] st, boolean mode) {
        for (int c=0; c<Nb; c++) {
            int col = ((st[0][c]&0xFF)<<24) | ((st[1][c]&0xFF)<<16)
                    | ((st[2][c]&0xFF)<< 8) |  (st[3][c]&0xFF);
            int res = mode ? MixCols.mix(col) : MixCols.invMix(col);
            for (int r=0; r<4; r++) {
                st[r][c] = (res >>> (24-8*r)) & 0xFF;
            }
        }
    }

    private void addRoundKey(int[][] st, int[][] rk) {
        for (int r=0;r<4;r++) for (int c=0;c<Nb;c++) {
            st[r][c] ^= rk[r][c];
        }
    }

    // --- helpers ---
    private static String bytesToHex(byte[] b) {
        char[] hex = "0123456789abcdef".toCharArray();
        char[] out = new char[b.length*2];
        for (int i=0;i<b.length;i++) {
            int v = b[i]&0xFF;
            out[i*2]   = hex[v>>>4];
            out[i*2+1] = hex[v & 0x0F];
        }
        return new String(out);
    }
    private static byte[] hexToBytes(String s) {
        byte[] out = new byte[s.length()/2];
        for (int i=0;i<out.length;i++) {
            int hi = Character.digit(s.charAt(2*i),16);
            int lo = Character.digit(s.charAt(2*i+1),16);
            out[i] = (byte)((hi<<4)|lo);
        }
        return out;
    }
    private void printState(String step, int[][] st) {
        System.out.println(step);
        for (int r=0;r<4;r++) {
            for (int c=0;c<Nb;c++) {
                System.out.printf("%02x", st[r][c]);
            }
            System.out.println();
        }
        System.out.println();
    }
}
