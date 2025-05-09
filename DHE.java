import java.math.BigInteger;
import java.util.Random;

public class DHE {
    private final BigInteger prime;
    private final BigInteger generator;

    public DHE(int gBits, int pBits) {
        System.out.printf("→ Generating a %d-bit safe prime…%n", pBits);
        BigInteger two = BigInteger.valueOf(2), q, pCand;
        do {
            q = Crypto.getPrime(pBits - 1, pBits - 1, 5);
            pCand = q.multiply(two).add(BigInteger.ONE);
        } while (!Crypto.checkPrime(pCand, 5));
        this.prime = pCand;
        System.out.println("✔ Safe prime ready." + prime);

        System.out.printf("→ Finding a generator (hint bits=%d)…%n", gBits);
        this.generator = Crypto.getGenerator(gBits, prime);
        System.out.println("✔ Generator found.");
    }

    public static BigInteger getPrime(int minBits, int maxBits, int numChecks) {
        return BigInteger.probablePrime(maxBits, new Random());
    }
    /**public BigInteger getPrime() {
        return prime;
    }*/

    public BigInteger getGenerator() {
        return generator;
    }

    public BigInteger getBase(int bits) {
        BigInteger priv;
        do {
            priv = Crypto.getRandom(bits, bits);
        } while (priv.compareTo(BigInteger.ONE) < 0 || priv.compareTo(prime) >= 0);
        return priv;
    }

    public BigInteger getExponent(BigInteger priv) {
        return Crypto.fastMod(generator, priv, prime);
    }

    public BigInteger getKey(BigInteger priv, BigInteger otherPub) {
        return Crypto.fastMod(otherPub, priv, prime);
    }

    public static void main(String[] args) {
        final int TEST_G = 16, TEST_P = 32;
        DHE dhe = new DHE(TEST_G, TEST_P);

        BigInteger a = dhe.getBase(TEST_G);
        BigInteger A = dhe.getExponent(a);
        BigInteger b = dhe.getBase(TEST_G);
        BigInteger B = dhe.getExponent(b);

        System.out.printf("A’s Private = %s%nPublic = %s%n", a, A);
        System.out.printf("B’s Private = %s%nPublic = %s%n", b, B);

        BigInteger keyA = dhe.getKey(a, B);
        BigInteger keyB = dhe.getKey(b, A);

        System.out.printf("Shared Key A: %s%nShared Key B: %s%n", keyA, keyB);
    }
}
