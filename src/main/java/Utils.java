import java.security.*;
import java.util.ArrayList;
import java.util.Base64;

public class Utils {
    public static String applySha256(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes("UTF-8"));
        StringBuilder hexString = new StringBuilder();
        for (final byte currentByte : hash) {
            String hex = Integer.toHexString(0xff & currentByte);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    //Applies ECDSA Signature and returns the result as bytes
    public static byte[] applyECDSASig(PrivateKey privateKey, String input) throws Exception {
        Signature ecdsa = Signature.getInstance("ECDSA", "BC");
        ecdsa.initSign(privateKey);
        ecdsa.update(input.getBytes());
        return ecdsa.sign();
    }

    //Verifies a String signature
    public static boolean verifyECDSASig(PublicKey publicKey, String data, byte[] signature) throws Exception {
        Signature ecdsaVerify = Signature.getInstance("ECDSA", "BC");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(data.getBytes());
        return ecdsaVerify.verify(signature);
    }

    public static String getStringFromKey(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static String getMerkleRoot(ArrayList<Transaction> transactions) throws Exception {
        int count = transactions.size();
        ArrayList<String> previousTreeLayer = new ArrayList<>();
        for (Transaction transaction : transactions) {
            previousTreeLayer.add(transaction.getTransactionId());
        }
        ArrayList<String> treeLayer = previousTreeLayer;
        while (count > 1) {
            treeLayer = new ArrayList<>();
            for (int i = 1; i < previousTreeLayer.size(); i++) {
                treeLayer.add(applySha256(previousTreeLayer.get(i - 1) + previousTreeLayer.get(i)));
            }
            count = treeLayer.size();
            previousTreeLayer = treeLayer;
        }
        return (treeLayer.size() == 1) ? treeLayer.get(0) : "";
    }
}