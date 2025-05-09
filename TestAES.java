/**
 * Smoke test for AES.java + MixCols.java + SBox.java
 */
public class TestAES {
    public static void main(String[] args) {
        String key       = "Thats my Kung Fu";      // 16-char = 128-bit
        String plaintext = "Two One Nine Two";      // 16 chars exactly
        AES aes = new AES(key, true);               // debug=true

        // --- ECB mode ---
        System.out.println("=== ECB ===");
        String ctECB = aes.encrypt(plaintext, false);
        System.out.println("Ciphertext: " + ctECB);
        String ptECB = aes.decrypt(ctECB, false).trim();
        System.out.println("Recovered : " + ptECB);

        // --- CBC mode ---
        System.out.println("\n=== CBC ===");
        String ctCBC = aes.encrypt(plaintext, true);
        System.out.println("Ciphertext: " + ctCBC);
        String ptCBC = aes.decrypt(ctCBC, true).trim();
        System.out.println("Recovered : " + ptCBC);
    }
}
