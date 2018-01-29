import java.security.PublicKey;
import java.util.*;
import java.util.stream.Collectors;

public class TxHandler {

    private UTXOPool unspentPool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.unspentPool = utxoPool != null ? new UTXOPool(utxoPool) : new UTXOPool();
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        boolean isValid = true;
        final Set<UTXO> usedUnspentOutputs = new HashSet<UTXO>();
        double inputSum = 0;

        int ind = 0;
        for(Transaction.Input input : tx.getInputs()) {
            // (1) all outputs claimed by {@code tx} are in the current UTXO pool
            UTXO unspentOutput = new UTXO(input.prevTxHash, input.outputIndex);
            isValid = isValid && this.unspentPool.contains(unspentOutput);
            if (!isValid) {
                return false;
            }

            //(2) the signatures on each input of {@code tx} are valid,
            Transaction.Output output = this.unspentPool.getTxOutput(unspentOutput);
            PublicKey publicKey = output.address;
            byte[] providedSignature = input.signature;
            if (publicKey == null || providedSignature == null) {
                return false;
            }
            byte[] signedMessage = tx.getRawDataToSign(ind++);
            isValid = isValid && Crypto.verifySignature(publicKey, signedMessage, providedSignature);

            //(3) no UTXO is claimed multiple times by {@code tx}
            isValid = isValid && !usedUnspentOutputs.contains(unspentOutput);
            usedUnspentOutputs.add(unspentOutput);

            inputSum += output.value;
        }
        //(4) all of {@code tx}s output values are non-negative, and
        double outputSum = 0;
        for(Transaction.Output output : tx.getOutputs()) {
            double outputValue = output.value;
            isValid = isValid && !(outputValue < 0);
            outputSum += outputValue;
        }

        //(5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
        isValid = isValid && !(inputSum < outputSum);

        return isValid;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        if (possibleTxs == null) {
            return new Transaction[0];
        }
        List<Transaction> approvedTransactions = new ArrayList<>();
        TxGraph txGraph = TxGraph.createDAG(possibleTxs);
        Transaction[] sortedTx = txGraph.getTopologicalSortedTx();

        for (Transaction transaction : sortedTx) {
            if (isValidTx(transaction)) {
                for (Transaction.Input input : transaction.getInputs()) {
                    final UTXO unspentOutput = new UTXO(input.prevTxHash, input.outputIndex);
                    this.unspentPool.removeUTXO(unspentOutput);
                }
                //transaction.finalize();
                byte[] hashTx = transaction.getHash();
                int ind = 0;
                for (Transaction.Output output : transaction.getOutputs()) {
                    this.unspentPool.addUTXO(new UTXO(hashTx, ind++), output);
                }
                approvedTransactions.add(transaction);
            }
        }

        return approvedTransactions.toArray(new Transaction[approvedTransactions.size()]);
    }

    public static class TxGraph {
        private Map<TxGraphKey, List<TxGraphKey>> edgesMap;
        private Map<TxGraphKey, Transaction> newTxMap;

        public TxGraph() {
            edgesMap = new HashMap<>();
            newTxMap = new HashMap<>();
        }

        public void addEdge(Transaction transaction) {
            TxGraphKey currentTxHash = new TxGraphKey(transaction.getHash());
            newTxMap.put(currentTxHash, transaction);
            for (Transaction.Input input : transaction.getInputs()) {
                addEdge(new TxGraphKey(input.prevTxHash), currentTxHash);
            }
        }

        public void addEdge(TxGraphKey parentTxKey, TxGraphKey childTxKey) {
            if (!edgesMap.containsKey(parentTxKey)) {
                edgesMap.put(parentTxKey, new ArrayList<>());
            }
            edgesMap.get(parentTxKey).add(childTxKey);
        }

        public static TxGraph createDAG(Transaction[] transactions) {
            final TxGraph graph = new TxGraph();
            for (Transaction transaction : transactions) {
                graph.addEdge(transaction);
            }
            return graph;
        }

        public Transaction[] getTopologicalSortedTx() {
            Stack<TxGraphKey> sortedTxs = new Stack<>();
            Set<TxGraphKey> visited = new HashSet<>();
            for (TxGraphKey vertex : edgesMap.keySet()) {
                topologicalSort(vertex, visited, sortedTxs);
            }
            List<Transaction> sorted = new ArrayList<>();
            while (!sortedTxs.empty()) {
                Transaction tx = newTxMap.get(sortedTxs.pop());
                if (tx != null) {
                    sorted.add(tx);
                }
            }

            return sorted.toArray(new Transaction[sorted.size()]);
        }

        public void topologicalSort(TxGraphKey vertex, Set<TxGraphKey> visited, Stack<TxGraphKey> sorted) {
            if (visited.contains(vertex)) {
                return;
            }
            visited.add(vertex);
            List<TxGraphKey> childTxs = edgesMap.get(vertex);
            if (childTxs != null) {
                for (TxGraphKey child : childTxs) {
                    topologicalSort(child, visited, sorted);
                }
            }
            if (newTxMap.containsKey(vertex)) {
                sorted.push(vertex);
            }
        }
    }

    public static class TxGraphKey {

        /** Hash of the transaction */
        private byte[] txHash;

        public TxGraphKey(byte[] txHash) {
            this.txHash = Arrays.copyOf(txHash, txHash.length);
        }

        public byte[] getTxHash() {
            return txHash;
        }

        public boolean equals(Object other) {
            if (other == null) {
                return false;
            }
            if (getClass() != other.getClass()) {
                return false;
            }

            TxGraphKey utxo = (TxGraphKey) other;
            byte[] hash = utxo.txHash;
            if (hash.length != txHash.length)
                return false;
            for (int i = 0; i < hash.length; i++) {
                if (hash[i] != txHash[i])
                    return false;
            }
            return true;
        }

        public int hashCode() {
            int hash = 1;
            hash = hash * 31 + Arrays.hashCode(txHash);
            return hash;
        }

        @Override
        public String toString() {
            return new String(txHash);
        }
    }

}
