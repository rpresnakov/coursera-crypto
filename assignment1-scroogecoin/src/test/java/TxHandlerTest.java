import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.security.PublicKey;
import java.util.stream.IntStream;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

import static org.junit.Assert.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ Crypto.class })
public class TxHandlerTest {

    private static UTXOPool POOL = new UTXOPool();

    @Mock
    private PublicKey testAddress;

    private static final byte[] TEST_SIGNATURE = new byte[0];
    private static final byte[] PREV_TX_HASH = "prevTx1".getBytes();
    private static final byte[] TEST_TX_HASH_1 = "Tx1".getBytes();
    private static final byte[] TEST_TX_HASH_2 = "Tx2".getBytes();
    private static final byte[] TEST_TX_HASH_3 = "Tx3".getBytes();

    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);
        PowerMockito.mockStatic(Crypto.class);
        PowerMockito.when(Crypto.verifySignature(any(PublicKey.class), any(byte[].class), any(byte[].class)))
                .thenReturn(true);
        when(testAddress.getEncoded()).thenReturn(new byte[0]);

        POOL = new UTXOPool();

        Transaction prevTx1 = new Transaction();
        prevTx1.setHash(PREV_TX_HASH);
        prevTx1.addOutput(10.0, testAddress);
        prevTx1.addOutput(15.0, testAddress);
        prevTx1.addOutput(20.0, testAddress);
        prevTx1.addOutput(30.0, testAddress);

        IntStream.range(0, prevTx1.numOutputs()).forEach(
                idx -> POOL.addUTXO(new UTXO(prevTx1.getHash(), idx), prevTx1.getOutput(idx))
        );
    }


    @Test
    public void testTransactionValidation() {
        TxHandler txHandler = new TxHandler(POOL);

        Transaction transaction1 = new Transaction();
        transaction1.setHash(TEST_TX_HASH_1);
        transaction1.addInput(PREV_TX_HASH, 0);
        transaction1.addSignature(TEST_SIGNATURE, 0);
        transaction1.addOutput(8.0, testAddress);
        transaction1.addOutput(2.0, testAddress);

        // sum of outputs bigger than input 16 vs 15
        Transaction transaction2 = new Transaction();
        transaction2.setHash(TEST_TX_HASH_2);
        transaction2.addInput(PREV_TX_HASH, 1);
        transaction2.addSignature(TEST_SIGNATURE, 0);
        transaction2.addOutput(14.0, testAddress);
        transaction2.addOutput(2.0, testAddress);

        //already claimed output
        Transaction transaction3 = new Transaction();
        transaction3.setHash(TEST_TX_HASH_3);
        transaction3.addInput(PREV_TX_HASH, 2);
        transaction3.addSignature(TEST_SIGNATURE, 0);
        transaction3.addInput(PREV_TX_HASH, 0);
        transaction3.addSignature(TEST_SIGNATURE, 1);
        transaction3.addOutput(19, testAddress);
        transaction3.addOutput(10, testAddress);

        Transaction[] requestedTxs = {transaction1, transaction2, transaction3};
        Transaction[] approved = txHandler.handleTxs(requestedTxs);

        assertNotNull(approved);
        assertEquals(approved.length, 1);
        byte[] txHash = approved[0].getHash();
        assertTrue(TEST_TX_HASH_1.equals(txHash) || TEST_TX_HASH_3.equals(txHash));
    }

    @Test
    public void testTransactionOrder() {
        TxHandler txHandler = new TxHandler(POOL);

        Transaction transaction1 = new Transaction();
        transaction1.setHash(TEST_TX_HASH_1);
        transaction1.addInput(PREV_TX_HASH, 0);
        transaction1.addSignature(TEST_SIGNATURE, 0);
        transaction1.addOutput(8.0, testAddress);

        //transaction 2 depends on transaction 1
        Transaction transaction2 = new Transaction();
        transaction2.setHash(TEST_TX_HASH_2);
        transaction2.addInput(TEST_TX_HASH_1, 0);
        transaction2.addSignature(TEST_SIGNATURE, 0);
        transaction2.addOutput(7.0, testAddress);

        //transaction 3 depends on transaction 2
        Transaction transaction3 = new Transaction();
        transaction3.setHash(TEST_TX_HASH_3);
        transaction3.addInput(TEST_TX_HASH_2, 0);
        transaction3.addSignature(TEST_SIGNATURE, 0);
        transaction3.addInput(PREV_TX_HASH, 1);
        transaction3.addSignature(TEST_SIGNATURE, 1);
        transaction3.addOutput(4, testAddress);
        transaction3.addOutput(2, testAddress);

        //given unordered list of transaction, however all of them are valid and should be processed
        Transaction[] requestedTxs = {transaction3, transaction1, transaction2};
        Transaction[] approved = txHandler.handleTxs(requestedTxs);

        assertNotNull(approved);
        assertEquals(3, approved.length);
    }

    @Test
    public void testMaxFeeTransactionOrder() {
        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(POOL);

        Transaction transaction1 = new Transaction();
        transaction1.setHash(TEST_TX_HASH_1);
        transaction1.addInput(PREV_TX_HASH, 0); // inp; 10.0
        transaction1.addInput(PREV_TX_HASH, 2); // inp; 20.0
        transaction1.addSignature(TEST_SIGNATURE, 0);
        transaction1.addSignature(TEST_SIGNATURE, 1);
        transaction1.addOutput(8.0, testAddress); // out: 8.0
        transaction1.addOutput(18.0, testAddress); // out: 18.0
        transaction1.addOutput(3.0, testAddress); // out: 3.0
        // fee: 1.0

        //transaction 2 depends on transaction 1
        Transaction transaction2 = new Transaction();
        transaction2.setHash(TEST_TX_HASH_2);
        transaction2.addInput(TEST_TX_HASH_1, 0); // in: 8 - Double Spend
        transaction2.addSignature(TEST_SIGNATURE, 0);
        transaction2.addOutput(5.0, testAddress); // out: 5
        // fee: 3

        Transaction transaction2_1 = new Transaction();
        transaction2_1.setHash("tx2_1".getBytes());
        transaction2_1.addInput(TEST_TX_HASH_2, 0); // in: 5 - Double Spend
        transaction2_1.addSignature(TEST_SIGNATURE, 0);
        transaction2_1.addInput(PREV_TX_HASH, 3); // in: 30 - Double Spend
        transaction2_1.addSignature(TEST_SIGNATURE, 1);
        transaction2_1.addOutput(10.0, testAddress); // out: 36
        // fee: -1

        //transaction 3 depends on transaction 1
        Transaction transaction3 = new Transaction();
        transaction3.setHash(TEST_TX_HASH_3);
        transaction3.addInput(TEST_TX_HASH_1, 0); // in: 8 - Double Spend
        transaction3.addSignature(TEST_SIGNATURE, 0);
        transaction3.addInput(PREV_TX_HASH, 1); // in: 15
        transaction3.addSignature(TEST_SIGNATURE, 1);
        transaction3.addOutput(4, testAddress); // out: 4
        transaction3.addOutput(2, testAddress); // out: 2
        // fee: 17

        //given unordered list of transaction, however all of them are valid and should be processed
        Transaction[] requestedTxs = {transaction3, transaction1, transaction2, transaction2_1};
        Transaction[] approved = txHandler.handleTxs(requestedTxs);

        assertNotNull(approved);
        assertEquals(3, approved.length);
        assertEquals(transaction1, approved[0]);
        assertEquals(transaction2, approved[1]);
        assertEquals(transaction2_1, approved[2]);
    }

    @Test
    public void testMaxFeeTransactionOrderWithInvalidTxs() {
        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(POOL);

        Transaction transaction1 = new Transaction();
        transaction1.setHash(TEST_TX_HASH_1);
        transaction1.addInput(PREV_TX_HASH, 0); // inp; 10.0
        transaction1.addInput(PREV_TX_HASH, 2); // inp; 20.0
        transaction1.addSignature(TEST_SIGNATURE, 0);
        transaction1.addSignature(TEST_SIGNATURE, 1);
        transaction1.addOutput(8.0, testAddress); // out: 8.0
        transaction1.addOutput(18.0, testAddress); // out: 18.0
        transaction1.addOutput(3.0, testAddress); // out: 3.0
        // fee: 1.0

        //transaction 2 depends on transaction 1
        Transaction transaction2 = new Transaction();
        transaction2.setHash(TEST_TX_HASH_2);
        transaction2.addInput(TEST_TX_HASH_1, 0); // in: 8 - Double Spend
        transaction2.addSignature(TEST_SIGNATURE, 0);
        transaction2.addOutput(5.0, testAddress); // out: 5
        // fee: 3

        Transaction transaction2_1 = new Transaction();
        transaction2_1.setHash("tx2_1".getBytes());
        transaction2_1.addInput(TEST_TX_HASH_2, 0); // in: 5 - Double Spend
        transaction2_1.addSignature(TEST_SIGNATURE, 0);
        transaction2_1.addInput(PREV_TX_HASH, 3); // in: 30 - Double Spend
        transaction2_1.addSignature(TEST_SIGNATURE, 1);
        transaction2_1.addOutput(36.0, testAddress); // out: 36
        // fee: -1

        Transaction transaction2_2 = new Transaction();
        transaction2_2.setHash("tx2_2".getBytes());
        transaction2_2.addInput("tx2_1".getBytes(), 0); // in: 36 - Double Spend
        transaction2_2.addSignature(TEST_SIGNATURE, 0);
        transaction2_2.addOutput(10.0, testAddress); // out: 10
        // fee: 26

        //transaction 3 depends on transaction 1
        Transaction transaction3 = new Transaction();
        transaction3.setHash(TEST_TX_HASH_3);
        transaction3.addInput(TEST_TX_HASH_1, 0); // in: 8 - Double Spend
        transaction3.addSignature(TEST_SIGNATURE, 0);
        transaction3.addInput(PREV_TX_HASH, 1); // in: 15
        transaction3.addSignature(TEST_SIGNATURE, 1);
        transaction3.addOutput(4, testAddress); // out: 4
        transaction3.addOutput(2, testAddress); // out: 2
        // fee: 17

        //given unordered list of transaction, however all of them are valid and should be processed
        Transaction[] requestedTxs = {transaction3, transaction1, transaction2, transaction2_1, transaction2_2};
        Transaction[] approved = txHandler.handleTxs(requestedTxs);

        assertNotNull(approved);
        assertEquals(2, approved.length);
        assertEquals(transaction1, approved[0]);
        assertEquals(transaction3, approved[1]);
    }

    @Test
    public void testMaxFeeTransactionOrder1() {
        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(POOL);

        Transaction transaction1 = new Transaction();
        transaction1.setHash(TEST_TX_HASH_1);
        transaction1.addInput(PREV_TX_HASH, 0); // inp; 10.0
        transaction1.addSignature(TEST_SIGNATURE, 0);
        transaction1.addOutput(8.0, testAddress); // out: 8.0
        // fee: 2.0

        //transaction 2 depends on transaction 1
        Transaction transaction2 = new Transaction();
        transaction2.setHash(TEST_TX_HASH_2);
        transaction2.addInput(PREV_TX_HASH, 0); // in: 10 - Double Spend
        transaction2.addSignature(TEST_SIGNATURE, 0);
        transaction2.addOutput(6.0, testAddress); // out: 5
        // fee: 4.0

        Transaction transaction2_1 = new Transaction();
        transaction2_1.setHash("tx2_1".getBytes());
        transaction2_1.addInput(PREV_TX_HASH, 0); // in: 10 - Double Spend
        transaction2_1.addSignature(TEST_SIGNATURE, 0);
        transaction2_1.addOutput(-1.0, testAddress); // out: 5
        // fee: 5

        //given unordered list of transaction, however all of them are valid and should be processed
        Transaction[] requestedTxs = {transaction2_1, transaction2, transaction1};
        Transaction[] approved = txHandler.handleTxs(requestedTxs);

        assertNotNull(approved);
        assertEquals(1, approved.length);
//        assertEquals(transaction1, approved[0]);
        assertEquals(transaction2, approved[0]);
//        assertEquals(transaction2_1, approved[2]);
    }
}
