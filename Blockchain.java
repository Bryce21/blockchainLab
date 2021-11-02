import java.net.*;
import java.util.*;
import java.io.*;
import java.util.concurrent.*;
// Ah, heck:
import java.security.KeyFactory;

/* CDE: The encryption needed for signing the hash: */

import java.security.KeyPair;
import java.security.KeyPairGenerator;
// Produces a 64-bye string representing 256 bits of the hash output. 4 bits per character
import java.security.MessageDigest; // To produce the SHA-256 hash.
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/* CDE Some other uitilities: */

import java.util.Date;
import java.util.Random;
import java.util.UUID;

import javax.crypto.Cipher;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class Blockchain {

    // which process number (0-2)
    int pnum;
    int numberProcesses = 3;
    String serverName = "localhost";

    // whether this Blockchain process sent keys
    boolean sentKey = false;
    KeyPair keyPair;

    // ArrayList to track known other processes and their public keys
    ArrayList<Process> knownProcesses = new ArrayList<Process>();

    LinkedList<BlockRecord> blockchain = new LinkedList<BlockRecord>();

    /* Token indexes for input: */
    private static final int iFNAME = 0;
    private static final int iLNAME = 1;
    private static final int iDOB = 2;
    private static final int iSSNUM = 3;
    private static final int iDIAG = 4;
    private static final int iTREAT = 5;
    private static final int iRX = 6;

    public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>() {
        @Override
        public int compare(BlockRecord b1, BlockRecord b2) {
            String s1 = b1.getTimeStamp();
            String s2 = b2.getTimeStamp();
            if (s1 == s2) {
                return 0;
            }
            if (s1 == null) {
                return -1;
            }
            if (s2 == null) {
                return 1;
            }
            return s1.compareTo(s2);
        }
    };

    final PriorityBlockingQueue<BlockRecord> unverifiedBlockQueue = new PriorityBlockingQueue<>(100, BlockTSComparator);

    public Blockchain(String args[]) {
    }

    public static void main(String args[]) {
        try {
            Blockchain bc = new Blockchain(args);
            bc.run(args);
        } catch (Exception x) {
            System.out.println(x.getMessage());
        }

    }

    public void run(String args[]) throws Exception {
        basicSetup(args);
        // registers other processes information
        apiKeysSetup();
        System.out.println("Known processes size: " + knownProcesses.size());

        // start unverified block listener
        new Thread(new UnverifiedBlockServer(unverifiedBlockQueue)).start();
        new Thread(new BlockchainServer(this)).start();

        // read input, create unverified blocks
        // realistically should not be blocking and should have it's own thread
        LinkedList<BlockRecord> unverifiedBlocks = getUnverifiedBlocks();
        System.out.println("Size of read blocks from file: " + unverifiedBlocks.size());

        // send the read unverified blocks to processes
        // read into priority queue
        sendUnverifiedBlocks(unverifiedBlocks);
        Thread.sleep(6000);

        // thread to start verifying blocks
        new Thread(new VerifyBlockWorker(this)).start();
        while (!unverifiedBlockQueue.isEmpty()) {
            System.out.println("Waiting for unverified block queue to empty... Size: " + unverifiedBlockQueue.size());
            Thread.sleep(3000);
        }
        System.out.println("Blockchain size after verification: " + blockchain.size());
        System.out.println("Unverified blocks queue after verification: " + unverifiedBlockQueue.size());
        // Add sleep to pretty much guarantee printing happens when done
        Thread.sleep(6000);
        // this prints blockchain to console
        printBlockchain();

    }

    public void WriteBlockChainToFile() {
        if (pnum == 0) {
            String filename = "p_0_blockchain.json";
            Gson gson = new GsonBuilder().setPrettyPrinting().create();

            // Convert the Java object to a JSON String:
            String json = gson.toJson(blockchain);

            System.out.println("\nJSON String blockRecord is: " + json);

            // Write the JSON object to a file:
            try (FileWriter writer = new FileWriter(filename)) {
                gson.toJson(blockchain, writer);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void printUnverifiedBlocksQueue() {
        System.out.println("Printing unverified block queue with size: " + unverifiedBlockQueue.size());
        Iterator queueIterator = unverifiedBlockQueue.iterator();
        while (queueIterator.hasNext()) {
            BlockRecord current = (BlockRecord) queueIterator.next();
            current.print();
        }
    }

    // return true if already in blockchain
    public boolean blockIsAlreadyInBlockchain(String blockId) {
        for (int i = 0; i < blockchain.size(); i++) {
            BlockRecord currentBlock = blockchain.get(i);
            if (currentBlock.BlockID.equals(blockId)) {
                return true;
            }
        }
        return false;
    }

    public void printBlockchain() {
        System.out.println("Printing block chain of size: " + blockchain.size() + " blockIds: ");
        System.out.println("blockInt,previousHash,winningHash,verifyingProcess,submittingProcess");
        for (int i = 0; i < blockchain.size(); i++) {
            BlockRecord currentBlock = blockchain.get(i);
            if (i == 0) {
                System.out.println(currentBlock.getBlockInteger() + "," + currentBlock.getPreviousHash() + ","
                        + currentBlock.getWinningHash() + "," + currentBlock.VerificationProcessID + ","
                        + currentBlock.SubmittingProcessID);
            } else {
                System.out.println(currentBlock.getBlockInteger() + "," + currentBlock.getPreviousHash().substring(0, 5)
                        + "," + currentBlock.getWinningHash().substring(0, 5) + "," + currentBlock.VerificationProcessID
                        + "," + currentBlock.SubmittingProcessID);
            }

        }
    }

    // returns true if signature is valid
    // returns false if signature is invalid
    // check that signed blockID is equal to blockID
    public boolean verifyUnverifiedBlockSignature(BlockRecord ub) throws NoSuchAlgorithmException, Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");

        // get the process that submitted this block
        Process parentProcess = findProcessByProcessId(ub.SubmittingProcessID);
        if (parentProcess == null) {
            return false;
        }
        // rebuild the public key from its bytes
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(parentProcess.publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey RestoredKey = keyFactory.generatePublic(pubSpec);

        signer.initVerify(RestoredKey);
        signer.update(ub.BlockID.getBytes());

        return signer.verify(ub.SignedBlockID);
    }

    public Process findProcessByProcessId(int parentProcessPnum) {
        for (int i = 0; i < knownProcesses.size(); i++) {
            Process currentProcess = knownProcesses.get(i);
            if (currentProcess.pnum == parentProcessPnum) {
                return currentProcess;
            }
        }
        System.out.println("Could not find knownProcess with pnum:" + parentProcessPnum);
        return null;
    }

    public boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initVerify(key);
        signer.update(data);

        return (signer.verify(sig));
    }

    // sends unverified blocks in this process to other processes
    // multicast unverified blocks into process queues
    public void sendUnverifiedBlocks(LinkedList<BlockRecord> unverifiedBlocks) {
        Socket UVBsock;
        Random r = new Random();
        try {
            Iterator<BlockRecord> iterator = unverifiedBlocks.iterator();

            // ObjectOutputStream toServerOOS = null;
            // PrintStream toServerOOS;
            for (int i = 0; i < numberProcesses; i++) {
                iterator = unverifiedBlocks.iterator();
                while (iterator.hasNext()) {
                    UVBsock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + (i * 1000));
                    PrintStream toServerOOS = new PrintStream(UVBsock.getOutputStream());
                    Thread.sleep((r.nextInt(9) * 100));
                    BlockRecord currentBlock = iterator.next();

                    // send the json string representing the currentBlock of the unverified blocks
                    // read in from file
                    toServerOOS.println(new Gson().toJson(currentBlock));
                    toServerOOS.flush();
                    UVBsock.close();
                }
            }
        } catch (Exception x) {
            x.printStackTrace();
        }
    }

    // reads in pnum, initializes ports, generates keys, initialize blockchain with
    // genesesis block
    public void basicSetup(String[] args) throws Exception {
        // set up process number
        pnum = readPNum(args);

        // initialize ports
        new Ports().setPorts(pnum);

        // get key information
        keyPair = generateKeyPair(new Random().nextLong());
        // System.out.println("Process: " + pnum + ", public key:" +
        // keyPair.getPublic());

        // genesis block has to always be the same for each process
        // so can't add in a lot of information
        BlockRecord genesisBlock = new BlockRecord();
        genesisBlock.setBlockID("genesisBlock");
        genesisBlock.setWinningHash("000000000");
        genesisBlock.setBlockInteger(0);
        blockchain.add(genesisBlock);
    }

    public void apiKeysSetup() throws Exception {
        // startup key listener
        // System.out.println("Process: " + pnum + ", starting api key listener");
        new Thread(new PublicKeyServer(this)).start();

        if (pnum == 2) {
            KeySend();
        }
        while (knownProcesses.size() < numberProcesses) {
            System.out.println(
                    "Waiting to contact other processes. Started by process with pnum 2 starting up... Known processes: "
                            + knownProcesses.size());
            Thread.sleep(3000);
        }
        System.out.println("Recieved other processes information");
    }

    public void sendVerifiedBlocks(BlockRecord verifiedBlock) {
        try {

            if (!blockIsAlreadyInBlockchain(verifiedBlock.BlockID)) {
                System.out.println("Sent verified blockID: " + verifiedBlock.BlockID + " from process: " + pnum);
                for (int i = 0; i < numberProcesses; i++) {
                    Socket BlockChainSock = new Socket(serverName, Ports.BlockchainServerPortBase + (i * 1000));
                    ObjectOutputStream toServer = new ObjectOutputStream(BlockChainSock.getOutputStream());
                    toServer.writeObject(verifiedBlock);
                    toServer.flush();
                    BlockChainSock.close();
                }
            }

        } catch (Exception e) {
            System.out.println("Exception sending verified block to other processes");
            e.printStackTrace();
        }

    }

    public void addProcess(Process process) {
        knownProcesses.add(process);
    }

    public static KeyPair generateKeyPair(long seed) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);

        return (keyGenerator.generateKeyPair());
    }

    public void KeySend() { // Multicast our public key to the other processes
        System.out.println("Key send started from pnum:" + pnum);
        Socket sock;
        PrintStream toServer;
        sentKey = true;
        try {
            for (int i = 0; i < numberProcesses; i++) {// Send our public key to all servers.
                sock = new Socket(serverName, Ports.KeyServerPortBase + (i * 1000));
                toServer = new PrintStream(sock.getOutputStream());

                Process thisProcess = new Process(pnum, keyPair.getPublic().getEncoded(), Ports.KeyServerPortBase,
                        serverName);

                String thisProcessJsonString = new Gson().toJson(thisProcess);

                // Send the process object representing this blockchain process
                toServer.println(thisProcessJsonString);
                toServer.flush();
                sock.close();
            }
        } catch (Exception x) {
            x.printStackTrace();
        }
    }

    public int readPNum(String args[]) {
        if (args.length < 1)
            return 0;
        else if (args[0].equals("0"))
            return 0;
        else if (args[0].equals("1"))
            return 1;
        else if (args[0].equals("2"))
            return 2;
        else
            return 0;
    }

    public String getFileName() {
        switch (pnum) {
        case 1:
            return "BlockInput1.txt";
        case 2:
            return "BlockInput2.txt";
        default:
            return "BlockInput0.txt";
        }
    }

    // returns a linked list of blockrecords read from file
    public LinkedList<BlockRecord> getUnverifiedBlocks() {
        String fileName = getFileName();
        System.out.println("Using input file: " + fileName);
        LinkedList<BlockRecord> recordList = new LinkedList<BlockRecord>();
        try {
            BufferedReader br = new BufferedReader(new FileReader(fileName));
            String[] tokens = new String[10];
            String InputLineStr;
            String suuid;
            UUID idA;
            BlockRecord tempRec;

            StringWriter sw = new StringWriter();

            int n = 0;

            while ((InputLineStr = br.readLine()) != null) {

                BlockRecord BR = new BlockRecord(); // Careful

                /* CDE For the timestamp in the block entry: */
                try {
                    Thread.sleep(1001);
                } catch (InterruptedException e) {
                }
                Date date = new Date();
                // String T1 = String.format("%1$s %2$tF.%2$tT", "Timestamp:", date);
                String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
                String TimeStampString = T1 + "." + pnum; // No timestamp collisions!
                // System.out.println("Timestamp: " + TimeStampString);
                BR.setTimeStamp(TimeStampString); // Will be able to priority sort by TimeStamp

                /*
                 * CDE: Generate a unique blockID. This would also be signed by creating
                 * process:
                 */
                suuid = new String(UUID.randomUUID().toString());
                BR.setBlockID(suuid);
                /* CDE put the file data into the block record: */
                tokens = InputLineStr.split(" +"); // Tokenize the input
                BR.setFname(tokens[iFNAME]);
                BR.setLname(tokens[iLNAME]);
                BR.setSSNum(tokens[iSSNUM]);
                BR.setDOB(tokens[iDOB]);
                BR.setDiag(tokens[iDIAG]);
                BR.setTreat(tokens[iTREAT]);
                BR.setRx(tokens[iRX]);
                BR.signBlockId(keyPair.getPrivate());

                // which process made this block
                BR.setSubmittingProcessID(pnum);

                recordList.add(BR);
                n++;
            }
            System.out.println(n + " records read." + "\n");

        } catch (Exception e) {
            e.printStackTrace();
        }
        return recordList;
    }

}

// Worker that runs when
class PublicKeyWorker extends Thread {
    Socket keySock;
    Blockchain containerBlockchainProcess;

    PublicKeyWorker(Socket s, Blockchain process) {
        keySock = s;
        containerBlockchainProcess = process;
    }

    public void run() {
        try {
            BufferedReader processIn = new BufferedReader(new InputStreamReader(keySock.getInputStream()));
            // Json string representation of Process class
            String stringProcess = processIn.readLine();
            // convert the string json to Process class object
            Process otherProcess = new Gson().fromJson(stringProcess, Process.class);

            containerBlockchainProcess.addProcess(otherProcess);
            keySock.close();
            if (!containerBlockchainProcess.sentKey) {
                // if the blockchain process has not sent its key send keys
                // ie if 0 or 1 process it needs to send its key to every process
                containerBlockchainProcess.KeySend();
            }
        } catch (Exception x) {
            x.printStackTrace();
        }
    }
}

class PublicKeyServer implements Runnable {
    // public ProcessBlock[] PBlock = new ProcessBlock[3]; // Typical would be: One
    // block to store info for each process.

    // represents the Blockchain process that started up this PublicKeyServer
    Blockchain containerBlockchainProcess;

    PublicKeyServer(Blockchain kBlockchain) {
        containerBlockchainProcess = kBlockchain;
    }

    public void run() {
        int q_len = 6;
        Socket keySock;
        try {
            ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);
            while (true) {
                keySock = servsock.accept();

                new PublicKeyWorker(keySock, containerBlockchainProcess).start();
            }
        } catch (IOException ioe) {
            System.out.println(ioe);
        }
    }
}

// Class that represents what info gets stored about a blockchain process
class Process implements Serializable {
    int pnum;
    byte[] publicKey;
    int port;
    String IPAddress;

    Process(int pnumParam, byte[] publicKeyParam, int portParam, String ipAdressParam) {
        this.pnum = pnumParam;
        this.publicKey = publicKeyParam;
        this.port = portParam;
        this.IPAddress = ipAdressParam;
    }

    public void printInfo() {
        System.out.println("pnum: " + pnum);
        // System.out.println("Public key: " + publicKey);
        System.out.println("port: " + port);
        System.out.println("ipAddress: " + IPAddress);
    }
}

class Ports {
    public static int KeyServerPortBase = 6050;
    public static int UnverifiedBlockServerPortBase = 6051;
    public static int BlockchainServerPortBase = 6052;

    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int BlockchainServerPort;

    public void setPorts(int PID) {
        KeyServerPort = KeyServerPortBase + (PID * 1000);
        UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + (PID * 1000);
        BlockchainServerPort = BlockchainServerPortBase + (PID * 1000);
    }
}

// class that represents the block record
class BlockRecord implements Serializable {
    /* Examples of block fields. You should pick, and justify, your own set: */
    String BlockID;
    byte[] SignedBlockID;
    String TimeStamp;
    int SubmittingProcessID;
    int VerificationProcessID;
    String PreviousHash; // We'll copy from previous block
    UUID uuid; // Just to show how JSON marshals this binary data.
    String Fname;
    String Lname;
    String SSNum;
    String DOB;
    String RandomSeed; // Our guess. Ultimately our winning guess.
    String WinningHash;
    String Diag;
    String Treat;
    String Rx;
    int blockInteger;

    /* Examples of accessors for the BlockRecord fields: */
    public String getBlockID() {
        return BlockID;
    }

    public void setBlockID(String BID) {
        this.BlockID = BID;
    }

    public String getTimeStamp() {
        return TimeStamp;
    }

    public void setTimeStamp(String TS) {
        this.TimeStamp = TS;
    }

    public int getSubmittingProcessID() {
        return SubmittingProcessID;
    }

    public void setSubmittingProcessID(int VID) {
        this.SubmittingProcessID = VID;
    }

    public void setVerificationProcessID(int VerificationProcessID) {
        this.VerificationProcessID = VerificationProcessID;
    }

    public int getVerificationProcessID() {
        return VerificationProcessID;
    }

    public String getPreviousHash() {
        return this.PreviousHash;
    }

    public void setPreviousHash(String PH) {
        this.PreviousHash = PH;
    }

    public UUID getUUID() {
        return uuid;
    }

    public void setUUID(UUID ud) {
        this.uuid = ud;
    }

    public String getLname() {
        return Lname;
    }

    public void setLname(String LN) {
        this.Lname = LN;
    }

    public String getFname() {
        return Fname;
    }

    public void setFname(String FN) {
        this.Fname = FN;
    }

    public String getSSNum() {
        return SSNum;
    }

    public void setSSNum(String SS) {
        this.SSNum = SS;
    }

    public String getDOB() {
        return DOB;
    }

    public void setDOB(String RS) {
        this.DOB = RS;
    }

    public String getDiag() {
        return Diag;
    }

    public void setDiag(String D) {
        this.Diag = D;
    }

    public String getTreat() {
        return Treat;
    }

    public void setTreat(String Tr) {
        this.Treat = Tr;
    }

    public String getRx() {
        return Rx;
    }

    public void setRx(String Rx) {
        this.Rx = Rx;
    }

    public String getRandomSeed() {
        return RandomSeed;
    }

    public void setRandomSeed(String RS) {
        this.RandomSeed = RS;
    }

    public String getWinningHash() {
        return WinningHash;
    }

    public void setWinningHash(String WH) {
        this.WinningHash = WH;
    }

    public void signBlockId(PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(getBlockID().getBytes());
        this.SignedBlockID = signer.sign();
    }

    public void print() {
        System.out.println("Printing information for Blockrecord: ");
        System.out.println("BlockId: " + BlockID);
        System.out.println("SubmittingProcessID: " + SubmittingProcessID);
        System.out.println("VerificationProcessID: " + VerificationProcessID);
        System.out.println("Timestmap: " + TimeStamp);
        System.out.println();
    }

    public int getBlockInteger() {
        return blockInteger;
    }

    public void setBlockInteger(int blockInteger) {
        this.blockInteger = blockInteger;
    }

    // return a string representing the block data
    // will be hashed together with random seed as a guess
    /*
     * String Fname; String Lname; String SSNum; String DOB; String RandomSeed; //
     * Our guess. Ultimately our winning guess. String WinningHash; String Diag;
     * String Treat; String Rx;
     */
    public String getDataForValidation() {
        // todo add the rest of the block data once sure this approach works
        return BlockID + SubmittingProcessID + Fname + Lname + SSNum;
    }

}

class BlockchainWorker extends Thread {
    Socket sock;
    Blockchain blockchainProcess;

    BlockchainWorker(Socket s, Blockchain blockChainProcess) {
        sock = s;
        this.blockchainProcess = blockChainProcess;
    }

    public void run() {
        try {
            ObjectInputStream verifiedBlock = new ObjectInputStream(sock.getInputStream());
            BlockRecord BR = (BlockRecord) verifiedBlock.readObject();

            // check that block chain doesn't already contain block
            if (!blockchainProcess.blockIsAlreadyInBlockchain(BR.BlockID)) {
                System.out.println("Adding BlockId to blockchain: " + BR.BlockID);
                blockchainProcess.blockchain.add(BR);
                blockchainProcess.WriteBlockChainToFile();
            }

            sock.close();
        } catch (Exception x) {
            x.printStackTrace();
        }
    }
}

class BlockchainServer implements Runnable {
    Blockchain blockChainProcess;

    BlockchainServer(Blockchain blockChainProcess) {
        this.blockChainProcess = blockChainProcess;
    }

    public void run() {
        int q_len = 6; /* Number of requests for OpSys to queue */
        Socket sock;
        try {
            ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
            while (true) {
                sock = servsock.accept();
                new BlockchainWorker(sock, blockChainProcess).start();
            }
        } catch (IOException ioe) {
            System.out.println(ioe);
        }
    }
}

class UnverifiedBlockServer implements Runnable {
    PriorityBlockingQueue<BlockRecord> queue;

    UnverifiedBlockServer(PriorityBlockingQueue<BlockRecord> queue) {
        this.queue = queue;
    }

    /*
     * Inner class to share priority queue. We are going to place the unverified
     * blocks (UVBs) into this queue in the order we get them, but they will be
     * retrieved by a consumer process sorted by TimeStamp of when created.
     */

    public void run() { // Start up the Unverified Block Receiving Server
        int q_len = 6; /* Number of requests for OpSys to queue */
        Socket sock;
        System.out.println("Starting the Unverified Block Server input thread using "
                + Integer.toString(Ports.UnverifiedBlockServerPort));
        try {
            ServerSocket UVBServer = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
            while (true) {
                sock = UVBServer.accept(); // Got a new unverified block
                // System.out.println("Got connection to UVB Server.");
                new UnverifiedBlockWorker(sock, queue).start(); // So start a thread to process it.
            }
        } catch (IOException ioe) {
            System.out.println(ioe);
        }
    }
}

class UnverifiedBlockWorker extends Thread {
    Socket sock;
    PriorityBlockingQueue<BlockRecord> queue;

    UnverifiedBlockWorker(Socket s, PriorityBlockingQueue<BlockRecord> queue) {
        sock = s;
        this.queue = queue;
    }

    public void run() {
        try {

            BufferedReader unverifiedBlockInput = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            // Json string representation of BlockRecord class for this unverified block
            String stringProcess = unverifiedBlockInput.readLine();
            // convert the string json to BlockRecord class object
            BlockRecord BR = new Gson().fromJson(stringProcess, BlockRecord.class);
            System.out
                    .println("Read in block id: " + BR.getBlockID() + " from process: " + BR.getSubmittingProcessID());
            queue.put(BR);
            sock.close();
        } catch (Exception x) {
            x.printStackTrace();
        }
    }
}

class VerifyBlockWorker implements Runnable {

    Blockchain parentProcess;

    int winningNumber = 20000;

    VerifyBlockWorker(Blockchain parentProcess) {
        this.parentProcess = parentProcess;
    }

    public static String randomAlphaNumeric(int count) {
        StringBuilder builder = new StringBuilder();
        while (count-- != 0) {
            int character = (int) (Math.random() * "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".length());
            builder.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".charAt(character));
        }
        return builder.toString();
    }

    // sleeps between 0-3 seconds
    public void randomSleep() throws Exception {
        Thread.sleep((new Random().nextInt(3) * 1000));
    }

    public static String ByteArrayToString(byte[] ba) {
        StringBuilder hex = new StringBuilder(ba.length * 2);
        for (int i = 0; i < ba.length; i++) {
            hex.append(String.format("%02X", ba[i]));
        }
        return hex.toString();
    }

    public void run() {
        System.out.println("Run called, size of unverified block queue: " + parentProcess.unverifiedBlockQueue.size());
        while (true) {
            if (!parentProcess.unverifiedBlockQueue.isEmpty()) {
                try {
                    // pop the unverified block
                    BlockRecord ub = parentProcess.unverifiedBlockQueue.poll();
                    // System.out.println("Popped block: " + ub.BlockID + "pnum: " +
                    // ub.SubmittingProcessID);

                    // if block already got added to block chain
                    // skip this iteration
                    if (parentProcess.blockIsAlreadyInBlockchain(ub.BlockID)) {
                        System.out.println("Block: " + ub.BlockID + " was already in blockchain, discarding it");
                        continue;
                    }

                    // todo do work
                    // work loop - will exit out as needed
                    while (true) {
                        // todo probably make this every three hash guesses or something
                        if (!parentProcess.verifyUnverifiedBlockSignature(ub)) {
                            System.out.println("Could not verify signature of block: " + ub.BlockID + " from process: "
                                    + ub.SubmittingProcessID);
                            break;
                        }
                        randomSleep();
                        String randString = randomAlphaNumeric(8);
                        String blockData = ub.getDataForValidation();

                        String previousHash = parentProcess.blockchain.getLast().getWinningHash();

                        String concatDataForHash = previousHash + blockData + randString;

                        MessageDigest MD = MessageDigest.getInstance("SHA-256");
                        byte[] bytesHash = MD.digest(concatDataForHash.getBytes("UTF-8"));

                        String stringHash = ByteArrayToString(bytesHash);

                        System.out.println("stringHash is: " + stringHash);
                        int intHash = Integer.parseInt(stringHash.substring(0, 4), 16);

                        if (intHash < winningNumber) {
                            System.out.println("Winning hash: " + stringHash);
                            ub.setVerificationProcessID(parentProcess.pnum);
                            ub.setWinningHash(stringHash);

                            // set previous hash... careful that blockchain is updated here
                            ub.setPreviousHash(parentProcess.blockchain.getLast().getWinningHash());
                            ub.setBlockInteger(parentProcess.blockchain.getLast().getBlockInteger() + 1);
                            ub.setRandomSeed(randString);
                            break;
                        }
                    }

                    // check that block is from a valid process
                    if (!parentProcess.verifyUnverifiedBlockSignature(ub)) {
                        System.out.println("Could not verify signature of block: " + ub.BlockID + " from process: "
                                + ub.SubmittingProcessID);
                        continue;
                    }
                    // if at this point ub is verified block now

                    parentProcess.sendVerifiedBlocks(ub);

                } catch (Exception x) {
                    x.printStackTrace();
                    continue;
                }

            }
        }
    }
}