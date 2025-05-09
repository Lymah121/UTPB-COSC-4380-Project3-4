import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class RSA {
    private BigInteger p, q, n, phi, e, d;

    public RSA(int bits) {
        p = Crypto.getPrime(bits / 2, bits / 2 + 1, 10);
        do {
            q = Crypto.getPrime(bits / 2, bits / 2 + 1, 10);
        } while (q.equals(p));

        n = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        e = BigInteger.valueOf(65537);
        while (!e.gcd(phi).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.valueOf(2));
        }
        d = Crypto.modularInverse(e, phi);
    }

    public String encrypt(String message, BigInteger pubE, BigInteger pubN) {
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        BigInteger msg = new BigInteger(1, bytes);
        return Crypto.fastMod(msg, pubE, pubN).toString(16);
    }

    public String decrypt(String ciphertext) {
        BigInteger cipher = new BigInteger(ciphertext, 16);
        BigInteger msg = Crypto.fastMod(cipher, d, n);
        byte[] bytes = msg.toByteArray();
        if (bytes[0] == 0) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            bytes = tmp;
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    public String sign(String hexText) {
        BigInteger m = new BigInteger(hexText, 16);
        return Crypto.fastMod(m, d, n).toString(16);
    }

    public String authenticate(String hexSig, BigInteger pubE, BigInteger pubN) {
        BigInteger s = new BigInteger(hexSig, 16);
        return Crypto.fastMod(s, pubE, pubN).toString(16);
    }

    public BigInteger[] getPublicKey() {
        return new BigInteger[]{e, n};
    }

    public BigInteger[] getPrivateKey() {
        return new BigInteger[]{d, n};
    }

    public static void main(String[] args) {
        RSA a = new RSA(512);
        RSA b = new RSA(512);

        String msg = "Hello RSA!";
        BigInteger[] bPub = b.getPublicKey();

        String cipher = a.encrypt(msg, bPub[0], bPub[1]);
        String signature = a.sign(cipher);

        String verified = b.authenticate(signature, a.getPublicKey()[0], a.getPublicKey()[1]);
        String decrypted = b.decrypt(verified);

        System.out.printf("Original: %s%nEncrypted: %s%nSignature: %s%nDecrypted: %s%n", msg, cipher, signature, decrypted);
    }
}
