// Crypto.java
import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.util.Scanner;

/**
 * <h1>Crypto</h1>
 * <p>Utility methods for DHE, RSA, and AES.</p>
 */
public class Crypto {
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger TWO = BigInteger.valueOf(2);

    /** Fast modular exponentiation (g^a mod p). */
    public static BigInteger fastMod(BigInteger g, BigInteger a, BigInteger p) {
        BigInteger result = ONE;
        BigInteger base   = g.mod(p);
        BigInteger exp    = a;
        while (exp.signum() > 0) {
            if (exp.testBit(0)) {
                result = result.multiply(base).mod(p);
            }
            base = base.multiply(base).mod(p);
            exp  = exp.shiftRight(1);
        }
        return result;
    }

    /** Is g a primitive root mod p (with p = 2q+1 safe prime)? */
    public static boolean isValidG(BigInteger g, BigInteger p) {
        BigInteger q = p.subtract(ONE).divide(TWO);
        if (g.modPow(TWO, p).equals(ONE)) return false;
        if (g.modPow(q,   p).equals(ONE)) return false;
        return true;
    }

    /** Find the smallest g ≥ 2 that’s a primitive root mod p. */
    public static BigInteger getGenerator(int bits, BigInteger p) {
        for (BigInteger g = TWO; g.compareTo(p) < 0; g = g.add(ONE)) {
            if (isValidG(g, p)) {
                return g;
            }
        }
        return null;
    }

    /** Random BigInteger with bitLength in (minBits, maxBits]. */
    public static BigInteger getRandom(int minBits, int maxBits) {
        BigInteger r = new BigInteger(maxBits, Rand.getRand());
        while (r.bitLength() <= minBits) {
            r = new BigInteger(maxBits, Rand.getRand());
        }
        return r;
    }

    /** Trial division + Fermat + Miller–Rabin primality test. */
    public static boolean checkPrime(BigInteger p, int numChecks) {
        if (p.compareTo(TWO) < 0)    return false;
        if (p.equals(TWO))           return true;
        if (p.mod(TWO).equals(ZERO)) return false;

        // trial division
        try (Scanner scan = new Scanner(new File("primes.txt"))) {
            while (scan.hasNext()) {
                BigInteger b = new BigInteger(scan.nextLine());
                if (p.mod(b).equals(ZERO)) {
                    return false;
                }
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        BigInteger pm = p.subtract(ONE);
        // Fermat tests
        for (int i = 0; i < numChecks; i++) {
            BigInteger a = getRandom(1, p.bitLength() - 1);
            if (!fastMod(a, pm, p).equals(ONE)) {
                return false;
            }
        }

        // Miller–Rabin
        BigInteger d = pm;
        int s = 0;
        while (d.mod(TWO).equals(ZERO)) {
            d = d.shiftRight(1);
            s++;
        }
        for (int i = 0; i < numChecks; i++) {
            BigInteger a = getRandom(1, p.bitLength() - 1);
            BigInteger x = fastMod(a, d, p);
            if (x.equals(ONE) || x.equals(pm)) continue;
            boolean passed = false;
            for (int r = 1; r < s; r++) {
                x = x.multiply(x).mod(p);
                if (x.equals(pm)) {
                    passed = true;
                    break;
                }
            }
            if (!passed) return false;
        }
        return true;
    }

    /** Generate a prime in (minBits, maxBits] via checkPrime. */
    public static BigInteger getPrime(int minBits, int maxBits, int numChecks) {
        BigInteger p = getRandom(minBits, maxBits);
        while (!checkPrime(p, numChecks)) {
            p = getRandom(minBits, maxBits);
        }
        return p;
    }

    /** Generate a safe prime p = 2q+1 where q is prime. */
    public static BigInteger getSafePrime() {
        while (true) {
            BigInteger q = getPrime(2048, 3072, 10);
            BigInteger p = q.multiply(TWO).add(ONE);
            if (checkPrime(p, 10)) return p;
        }
    }

    /** Extended Euclidean algorithm; returns [gcd, x, y] for ax+by=gcd. */
    public static BigInteger[] extendedGCD(BigInteger a, BigInteger b) {
        if (b.equals(ZERO)) {
            return new BigInteger[]{a, ONE, ZERO};
        }
        BigInteger[] vals = extendedGCD(b, a.mod(b));
        BigInteger d = vals[0], x1 = vals[1], y1 = vals[2];
        BigInteger x = y1;
        BigInteger y = x1.subtract(a.divide(b).multiply(y1));
        return new BigInteger[]{d, x, y};
    }

    /** Modular inverse of e mod phi via extended GCD. */
    public static BigInteger modularInverse(BigInteger e, BigInteger phi) {
        BigInteger[] res = extendedGCD(e, phi);
        if (!res[0].equals(ONE)) {
            throw new ArithmeticException("No inverse");
        }
        return res[1].mod(phi);
    }
}
