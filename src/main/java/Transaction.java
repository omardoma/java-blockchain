import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;

public class Transaction {
    private String transactionId; //Contains a hash of transaction*
    private PublicKey sender;
    private PublicKey recipient;
    private float value;
    private byte[] signature;
    private ArrayList<TransactionInput> inputs;
    private ArrayList<TransactionOutput> outputs;
    private static int sequence = 0;

    public Transaction(PublicKey sender, PublicKey receiver, float value, ArrayList<TransactionInput> inputs) {
        this.sender = sender;
        this.recipient = receiver;
        this.value = value;
        this.inputs = inputs;
        this.outputs = new ArrayList<>();
    }

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public PublicKey getSender() {
        return sender;
    }

    public PublicKey getRecipient() {
        return recipient;
    }

    public float getValue() {
        return value;
    }

    public byte[] getSignature() {
        return signature;
    }

    public ArrayList<TransactionInput> getInputs() {
        return inputs;
    }

    public ArrayList<TransactionOutput> getOutputs() {
        return outputs;
    }

    public float getInputsValue() {
        float total = 0;
        for (TransactionInput i : inputs) {
            if (i.getUTXO() != null) {
                total += i.getUTXO().getValue();
            }
        }
        return total;
    }

    public void generateSignature(PrivateKey privateKey) throws Exception {
        String data = Utils.getStringFromKey(sender) + Utils.getStringFromKey(recipient) + Float.toString(value);
        signature = Utils.applyECDSASig(privateKey, data);
    }

    public boolean verifySignature() throws Exception {
        String data = Utils.getStringFromKey(sender) + Utils.getStringFromKey(recipient) + Float.toString(value);
        return Utils.verifyECDSASig(sender, data, signature);
    }

    public float getOutputsValue() {
        float total = 0;
        for (TransactionOutput o : outputs) {
            total += o.getValue();
        }
        return total;
    }

    private String calculateHash() throws Exception {
        sequence++; //increase the sequence to avoid 2 identical transactions having the same hash
        return Utils.applySha256(
                Utils.getStringFromKey(sender) +
                        Utils.getStringFromKey(recipient) +
                        Float.toString(value) + sequence
        );
    }

    public boolean processTransaction() throws Exception {
        if (!verifySignature()) {
            System.out.println("#Transaction Signature failed to verify");
            return false;
        }

        //Gathers transaction inputs (Making sure they are unspent):
        for (TransactionInput i : inputs) {
            i.setUTXO(Blockchain.UTXOs.get(i.getTransactionOutputId()));
        }

        //Checks if transaction is valid:
        if (getInputsValue() < Blockchain.MINIMUM_TRANSACTION) {
            System.out.println("Transaction Inputs too small: " + getInputsValue());
            System.out.println("Please enter the amount greater than " + Blockchain.MINIMUM_TRANSACTION);
            return false;
        }

        //Generate transaction outputs:
        float leftOver = getInputsValue() - value; //get value of inputs then the left over change:
        transactionId = calculateHash();
        outputs.add(new TransactionOutput(this.recipient, value, transactionId)); //send value to recipient
        outputs.add(new TransactionOutput(this.sender, leftOver, transactionId)); //send the left over 'change' back to sender

        //Add outputs to Unspent list
        for (TransactionOutput o : outputs) {
            Blockchain.UTXOs.put(o.getId(), o);
        }

        //Remove transaction inputs from UTXO lists as spent:
        for (TransactionInput i : inputs) {
            if (i.getUTXO() != null) {
                Blockchain.UTXOs.remove(i.getUTXO().getId());
            }
        }

        return true;
    }
}