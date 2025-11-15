public class Hill {

    public static int[][] keymat = new int[][]{
            {1, 2, 1},
            {2, 3, 2},
            {2, 2, 1}
    };

    public static int[][] invkeymat = new int[][]{
            {-1, 0, 1},
            {2, -1, 0},
            {-2, 2, -1}
    };

    public static String key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private static String encode(char a, char b, char c) {
        int posa = a - 65;
        int posb = b - 65;
        int posc = c - 65;

        int x = posa * keymat[0][0] + posb * keymat[1][0] + posc * keymat[2][0];
        int y = posa * keymat[0][1] + posb * keymat[1][1] + posc * keymat[2][1];
        int z = posa * keymat[0][2] + posb * keymat[1][2] + posc * keymat[2][2];

        char e1 = key.charAt(x % 26);
        char e2 = key.charAt(y % 26);
        char e3 = key.charAt(z % 26);

        return "" + e1 + e2 + e3;
    }

    private static String decode(char a, char b, char c) {
        int posa = a - 65;
        int posb = b - 65;
        int posc = c - 65;

        int x = posa * invkeymat[0][0] + posb * invkeymat[1][0] + posc * invkeymat[2][0];
        int y = posa * invkeymat[0][1] + posb * invkeymat[1][1] + posc * invkeymat[2][1];
        int z = posa * invkeymat[0][2] + posb * invkeymat[1][2] + posc * invkeymat[2][2];

        char d1 = key.charAt((x % 26 < 0) ? (26 + x % 26) : (x % 26));
        char d2 = key.charAt((y % 26 < 0) ? (26 + y % 26) : (y % 26));
        char d3 = key.charAt((z % 26 < 0) ? (26 + z % 26) : (z % 26));

        return "" + d1 + d2 + d3;
    }

    public static void main(String[] args) throws Exception {
        String msg = "SecurityLaboratory";
        String enc = "";
        String dec = "";

        System.out.println("simulation of Hill Cipher");
        System.out.println("-------------------------");
        System.out.println("Input message : " + msg);

        msg = msg.toUpperCase().replaceAll("\\s", "");

        int n = msg.length() % 3;
        if (n != 0) {
            for (int i = 1; i <= (3 - n); i++) {
                msg += 'X';
            }
        }

        System.out.println("padded message : " + msg);

        char[] pdchars = msg.toCharArray();
        for (int i = 0; i < msg.length(); i += 3) {
            enc += encode(pdchars[i], pdchars[i + 1], pdchars[i + 2]);
        }

        System.out.println("encoded message : " + enc);

        char[] dechars = enc.toCharArray();
        for (int i = 0; i < enc.length(); i += 3) {
            dec += decode(dechars[i], dechars[i + 1], dechars[i + 2]);
        }

        System.out.println("decoded message : " + dec);
    }
}
