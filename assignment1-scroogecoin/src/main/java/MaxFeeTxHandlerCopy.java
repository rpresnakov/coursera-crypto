import java.security.PublicKey;
import java.util.*;

public class MaxFeeTxHandlerCopy {

    private UTXOPool unspentPool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public MaxFeeTxHandlerCopy(UTXOPool utxoPool) {
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
        TxGraph txGraph = TxGraph.createDAG(possibleTxs, unspentPool);
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
        private UTXOPool outputPool;
        private Map<TxGraphKey, Set<TxGraphKey>> edgesMap;
        private Map<TxGraphKey, Transaction> newTxMap;

        private Map<TxGraphKey, Double> feesCache;
        private Map<TxGraphKey, Set<UTXO>> doubleSpendingMap;
        private Map<UTXO, TxGraphKey> doubleSpendDetector;

        private MaxFeeTxHandlerCopy innerTxValidator;

        public TxGraph(UTXOPool pool) {
            outputPool = new UTXOPool(pool);
            edgesMap = new HashMap<>();
            newTxMap = new HashMap<>();
            doubleSpendingMap = new HashMap<>();
            doubleSpendDetector = new HashMap<>();
            feesCache = new HashMap<>();
        }

        public void addIntoPool(UTXO utxo, Transaction.Output output) {
            outputPool.addUTXO(utxo, output);
        }

        public void addEdge(Transaction transaction) {
            final TxGraphKey currentTxHash = new TxGraphKey(transaction.getHash());
            for (Transaction.Input input : transaction.getInputs()) {
                final UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
                final TxGraphKey prevTxKey = new TxGraphKey(input.prevTxHash);

                // adding all outputs into internal pool to calculate fees further
                Transaction prevTx = newTxMap.get(prevTxKey);
                if (prevTx != null) {
                    addIntoPool(utxo, prevTx.getOutput(utxo.getIndex()));
                }
                // detect and mark potential double spenders
                detectDoubleSpenders(utxo, currentTxHash);

                addEdge(prevTxKey, currentTxHash);
            }
        }

        public void addEdge(TxGraphKey parentTxKey, TxGraphKey childTxKey) {
            if (!edgesMap.containsKey(parentTxKey)) {
                edgesMap.put(parentTxKey, new HashSet<>());
            }
            edgesMap.get(parentTxKey).add(childTxKey);
        }

        public void detectDoubleSpenders(UTXO utxo, TxGraphKey childTxKey) {
            doubleSpendingMap.put(childTxKey, new HashSet<>());
            // if UTXO is used for the first time just put it to doubleSpendDetector map
            if (!doubleSpendDetector.containsKey(utxo)) {
                doubleSpendDetector.put(utxo, childTxKey);
            } else {
                // if UTXO was already used in any previous transaction let's mark child tx as doubleSpender.
                doubleSpendingMap.get(childTxKey).add(utxo);
                TxGraphKey anotherCandidate = doubleSpendDetector.get(utxo);
                doubleSpendingMap.get(anotherCandidate).add(utxo);
            }
        }

        public static TxGraph createDAG(Transaction[] transactions, UTXOPool pool) {
            final TxGraph graph = new TxGraph(pool);
            for (Transaction transaction : transactions) {
                graph.newTxMap.put(new TxGraphKey(transaction.getHash()), transaction);
            }
            for (Transaction transaction : transactions) {
                graph.addEdge(transaction);
            }
            graph.innerTxValidator = new MaxFeeTxHandlerCopy(graph.outputPool);
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

        public double topologicalSort(TxGraphKey vertex, Set<TxGraphKey> visited, Stack<TxGraphKey> sorted) {
            if (visited.contains(vertex)) {
                return feesCache.get(vertex);
            }
            visited.add(vertex);
            Set<TxGraphKey> childTxs = edgesMap.get(vertex);
            double sumFee = 0.0;
            if (childTxs != null) {
                double fee;
                Map<TxGraphKey, Double> maxValue = new HashMap<>();
                for (TxGraphKey child : childTxs) {
                    fee = topologicalSort(child, visited, sorted);
                    if (!doubleSpendingMap.get(child).isEmpty()) {
                        // if child marked as double spender then:
                        Set<UTXO> utxos = doubleSpendingMap.get(child);
                        TxGraphKey keyToRemove = null;
                        if (maxValue.isEmpty()) {
                            maxValue.put(child, fee);
                            continue;
                        }
                        for (TxGraphKey key : maxValue.keySet()) {
                            double max = fee;
                            Set<UTXO> otherUtxos = doubleSpendingMap.get(key);
                            if (checkMergedSets(utxos, otherUtxos)) {
                                // if we found another double spender in the map
                                double existingMax = maxValue.get(key);
                                if (max > existingMax) {
                                    maxValue.put(child, max);
                                    keyToRemove = key;
                                } else {
                                    keyToRemove = child;
                                }
                                break;
                            }
                        }
                        // check if we need to remove double spender with min fee
                        if (keyToRemove != null) {
                            maxValue.remove(keyToRemove);
                            sorted.remove(keyToRemove);
                        }
                    } else {
                        // if child is not double spender sum up the fee
                        sumFee += fee;
                    }
                }
            }
            if (newTxMap.containsKey(vertex)) {
                Transaction tx = newTxMap.get(vertex);
                if (innerTxValidator.isValidTx(tx)) {
                    sorted.push(vertex);
                    sumFee += calculateFee(vertex);
                } else {
                    sumFee = 0;
                }
                feesCache.put(vertex, sumFee);
            }
            return sumFee;
        }

        public static <T> boolean checkMergedSets(Set<T> set1, Set<T> set2) {
            for (T el : set1) {
                if (set2.contains(el)) {
                    return true;
                }
            }
            return false;
        }

        public double calculateFee(TxGraphKey txGraphKey) {
            Transaction tx = newTxMap.get(txGraphKey);
            double inp = 0.0;
            double out = 0.0;
            for (Transaction.Input input : tx.getInputs()) {
                inp += outputPool.getTxOutput(new UTXO(input.prevTxHash, input.outputIndex)).value;
            }
            for (Transaction.Output output : tx.getOutputs()) {
                out += output.value;
            }
            double fee = (inp - out);
            return fee;
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
