import java.net.*;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.util.*;
import java.io.*;
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

// import com.google.gson.Gson;
// import com.google.gson.GsonBuilder;

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

    /* Token indexes for input: */
    private static final int iFNAME = 0;
    private static final int iLNAME = 1;
    private static final int iDOB = 2;
    private static final int iSSNUM = 3;
    private static final int iDIAG = 4;
    private static final int iTREAT = 5;
    private static final int iRX = 6;

    public Blockchain(String args[]) {
        System.out.println("In the constructor...");
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
        apiKeysSetup();
        readInput();
    }

    public void basicSetup(String[] args) throws Exception {
        // set up process number
        pnum = readPNum(args);
        System.out.println("Process number is: " + pnum);

        // initialize ports
        new Ports().setPorts(pnum);

        // get key information
        keyPair = generateKeyPair(new Random().nextLong());
        System.out.println("Process: " + pnum + ", public key:" + keyPair.getPublic());
    }

    public void apiKeysSetup() throws Exception {
        // startup key listener
        System.out.println("Process: " + pnum + ", starting api key listener");
        new Thread(new PublicKeyServer(this)).start();

        if (pnum == 2) {
            KeySend();
        }
        System.out.println("Past key send");
        while (knownProcesses.size() == 0) {
            System.out.println("Waiting to contact other processes. Started by process with pnum 2 starting up...");
            Thread.sleep(3000);
        }
        System.out.println("Recieved other processes information");
        // knownProcesses.get(0).printInfo();
        // knownProcesses.get(1).printInfo();
        // knownProcesses.get(2).printInfo();
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
        ObjectOutputStream toServer;
        sentKey = true;
        try {
            for (int i = 0; i < numberProcesses; i++) {// Send our public key to all servers.
                sock = new Socket(serverName, Ports.KeyServerPortBase + (i * 1000));
                toServer = new ObjectOutputStream(sock.getOutputStream());

                // Send the process object representing this blockchain process
                toServer.writeObject(new Process(pnum, keyPair.getPublic(), Ports.KeyServerPortBase, serverName));
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
    public LinkedList<BlockRecord> readInput() {
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
                System.out.println("Timestamp: " + TimeStampString);
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

                // which process made this block
                BR.setVerificationProcessID(Integer.toString(pnum));

                recordList.add(BR);
                n++;
            }
            System.out.println(n + " records read." + "\n");
            System.out.println("Records in the linked list:");

            // Show names from records read into the linked list:
            Iterator<BlockRecord> iterator = recordList.iterator();
            while (iterator.hasNext()) {
                tempRec = iterator.next();
                System.out.println(tempRec.getTimeStamp() + " " + tempRec.getFname() + " " + tempRec.getLname());
            }
            System.out.println("");

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
            ObjectInputStream unverifiedIn = new ObjectInputStream(keySock.getInputStream());
            Process otherProcess = (Process) unverifiedIn.readObject();
            containerBlockchainProcess.addProcess(otherProcess);
            keySock.close();
            if (!containerBlockchainProcess.sentKey) {
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
        System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
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
    PublicKey publicKey;
    int port;
    String IPAddress;

    Process(int pnumParam, PublicKey publicKeyParam, int portParam, String ipAdressParam) {
        this.pnum = pnumParam;
        this.publicKey = publicKeyParam;
        this.port = portParam;
        this.IPAddress = ipAdressParam;
    }

    public void printInfo() {
        System.out.println("pnum: " + pnum);
        System.out.println("Public key: " + publicKey);
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
class BlockRecord {
    /* Examples of block fields. You should pick, and justify, your own set: */
    String BlockID;
    String TimeStamp;
    String VerificationProcessID;
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

    public String getVerificationProcessID() {
        return VerificationProcessID;
    }

    public void setVerificationProcessID(String VID) {
        this.VerificationProcessID = VID;
    }

    public String getPreviousHash() {
        return this.PreviousHash;
    }

    public void setPreviousHash(String PH) {
        this.PreviousHash = PH;
    }

    public UUID getUUID() {
        return uuid;
    } // Later will show how JSON marshals as a string. Compare to BlockID.

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

}