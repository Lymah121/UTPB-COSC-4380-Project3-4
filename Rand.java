// Rand.java
import java.security.SecureRandom;

public class Rand {
    private static SecureRandom rand;

    static {
        try {
            rand = SecureRandom.getInstance("SHA1PRNG");
        } catch (Exception e) {
            rand = new SecureRandom();
        }
    }

    /** Get the singleton SecureRandom. */
    public static SecureRandom getRand() {
        return rand;
    }

    /** Uniform int in [0, max). */
    public static int randInt(int max) {
        return rand.nextInt(max);
    }

    /** Uniform int in [min, max], inclusive. */
    public static int randInt(int min, int max) {
        return rand.nextInt(max - min + 1) + min;
    }

    /** Uniform non-negative long. */
    public static long randLong() {
        long x = rand.nextLong();
        return (x == Long.MIN_VALUE) ? 0L : Math.abs(x);
    }

    /** Gaussian with mean and stddev. */
    public static double randGauss(double mean, double stddev) {
        return mean + stddev * rand.nextGaussian();
    }

    /** Random bit-array of length len. */
    public static boolean[] randBits(int len) {
        boolean[] bits = new boolean[len];
        for (int i = 0; i < len; i++) {
            bits[i] = rand.nextBoolean();
        }
        return bits;
    }
}
