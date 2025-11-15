public class Caesar {

    public static String encode(String enc, int offset) {
        offset = offset % 26 + 26;
        StringBuilder encoded = new StringBuilder();
        for (char c : enc.toCharArray()) {
            if (Character.isLetter(c)) {
                if (Character.isUpperCase(c)) {
                    encoded.append((char) ('A' + (c - 'A' + offset) % 26));
                } else {
                    encoded.append((char) ('a' + (c - 'a' + offset) % 26));
                }
            } else {
                encoded.append(c);
            }
        }
        return encoded.toString();
    }

    public static String decode(String enc, int offset) {
        return encode(enc, 26 - offset);
    }

    public static void main(String[] args) throws Exception {
        String msg = "Anna University";
        System.out.println("Simulating Caesar Cipher");
        System.out.println("------------------------");
        System.out.println("Input : " + msg);
        System.out.print("Encrypted Message : ");
        System.out.println(CaesarCipher.encode(msg, 3));
        System.out.print("Decrypted Message : ");
        System.out.println(CaesarCipher.decode(CaesarCipher.encode(msg, 3), 3));
    }
}
