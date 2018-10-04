import java.util.*;
import java.io.*;
import java.security.*;
import java.nio.*;
import java.security.spec.*;


public class StringCoin{

	public static void main(String args[]) throws Exception{

		if(args.length != 1) {
			System.out.println("Need more arguments plzzz");
			System.exit(1);
		}

		String billpublickey = "3081f03081a806072a8648ce38040130819c024100fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17021500962eddcc369cba8ebb260ee6b6a126d9346e38c50240678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca403430002405b0656317dd257ec71982519d38b42c02621290656eba54c955704e9b5d606062ec663bdeef8b79daa2631287d854da77c05d3e178c101b2f0a1dbbe5c7d5e10";

		// Initialize HashMap structure for ID/Owners
		HashMap<String, String> coins = new HashMap<>();

		// Count variable to traverse blockchain
		int count = 0;

		// First coin's previous hash starts with "0", so initializing for laziness
		String previousHash = "0";

		// Initialize blockchain
		LinkedList<block> blockChain = initializeBlockchain(args[0]);

		while(count < blockChain.size()) {

			// Traverse blockchain from beginning
			block currentBlock = blockChain.get(count);

			if(currentBlock.getType().equals("CREATE")){

				// If the coin already exists, then exit
				if(coins.containsKey(currentBlock.getCoinID())) {
					System.out.println("Coin " + currentBlock.getCoinID() + "exists");
					System.out.println("This Blockchain is WHACK");
					System.exit(1);
				}
				// If the block signature verification is wrong, exit
				else if(!PublicKeyDemo.verifyMessage(currentBlock.getLine(), currentBlock.getSig(), billpublickey) && !currentBlock.getCoinID().equals("0000")) {
					System.out.println("This Blockchain is WHACK");
					System.exit(1);
				}
				// If the block's previous hash attribute doesn't match the actual previous hash, exit
				else if(!currentBlock.getPrevious().equals(previousHash) && !currentBlock.getPrevious().equals("0")){
					System.out.println("This Blockchain is WHACK");
				}
				// After all the checks, insert block into Hashmap of coins
				coins.put(currentBlock.getCoinID(), billpublickey);
				// Calculate hash of previous line
				previousHash = Sha256Hash.calculateHash(currentBlock.getEntireLine());

			}
			else if(currentBlock.getType().equals("TRANSFER")){
				// If the block signature verification is wrong, exit
				if(!PublicKeyDemo.verifyMessage(currentBlock.getLine(), currentBlock.getSig(), coins.get(currentBlock.getCoinID()))){
					System.out.println("This Blockchain is WHACK");
					System.exit(1);
				}
				// If the block's previous hash attribute doesn't match the actual previous hash, exit
				else if(!currentBlock.getPrevious().equals(previousHash) && !currentBlock.getPrevious().equals("0")){
					System.out.println("This Blockchain is WHACK");
					System.exit(1);
				}
				// After all the checks, insert block into Hashmap of coins
				coins.put(currentBlock.getCoinID(), currentBlock.getCoinSig());
				// Calculate hash of previous line
				previousHash = Sha256Hash.calculateHash(currentBlock.getEntireLine());
			}
			else{
				System.out.println("This Blockchain is WHACK");
				System.exit(1);
			}
			count++;
		}

		// Initialize TreeMap to sort Coins in numerical order
		Map<String, String> sortedHash = new TreeMap<>(coins);

		// Add coins to new TreeMap and print out sorted order
		sortedHash.forEach((coin, owner) -> System.out.println("Coin " + coin + " / Owner = " + owner));

		System.exit(0);
	}

	// Function to read in file of coin blocks
	public static LinkedList<block> initializeBlockchain(String file) throws Exception{
		// Makin dat blockchain linked list
		LinkedList<block> blockchain = new LinkedList<>();
		String line;
		String[] lineInformation;
		Scanner scanny = new Scanner(new File(file));

		while(scanny.hasNextLine()){
			line = scanny.nextLine();
			lineInformation = line.split(",");
			blockchain.add(new block(lineInformation));
		}
		scanny.close();
		return blockchain;
	}
}

class PublicKeyDemo{

    public static byte[] convertHexToBytes(String hex) {
		byte[] bytes = new byte[hex.length() / 2];
		int c = 0;
		for (int j = 0; j < hex.length(); j += 2) {
		    String twoHex = hex.substring(j, j + 2);
		    byte byteVal = (byte) Integer.parseInt(twoHex, 16);
		    bytes[c++] = byteVal;
		}
		return bytes;
    }


    public static KeyPair getKeyPair() throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
		SecureRandom random = new SecureRandom(); // .getInstance("SHA1PRNG", "SUN");
		keyGen.initialize(1024, random);
		return keyGen.generateKeyPair();
    }


    public static PublicKey loadPublicKey(String stored) throws Exception {
    	byte[] data = convertHexToBytes(stored);
    	X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
    	KeyFactory fact = KeyFactory.getInstance("DSA");
    	return fact.generatePublic(spec);
    }


    public static PrivateKey loadPrivateKey(String stored) throws Exception {
		byte[] data = convertHexToBytes(stored);
	    	KeyFactory keyFactory=KeyFactory.getInstance("DSA");
		PrivateKey privKey=keyFactory.generatePrivate(new PKCS8EncodedKeySpec(data));
		return privKey;
    }


    public static String signMessage(String msg, String key) throws Exception {
		PrivateKey sk = loadPrivateKey(key);
		byte[] sigBytes = sign(msg, sk);
		String toReturn = Sha256Hash.convertBytesToHexString(sigBytes);
		return toReturn;
    }


    public static boolean verifyMessage(String msg, String sig, String key) throws Exception {
		PublicKey pk = loadPublicKey(key);
		byte[] sigBytes = convertHexToBytes(sig);
		boolean toReturn = verify(msg, sigBytes, pk);
		return toReturn;
    }


    public static byte[] sign(String toSign, PrivateKey sk) throws Exception {
		Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
		dsa.initSign(sk);

		byte[] bytes = toSign.getBytes();
		dsa.update(bytes, 0, bytes.length);
		byte[] sig = dsa.sign();
		return sig;
    }


    public static boolean verify(String toCheck, byte[] sig, PublicKey pk) throws Exception {
	    Signature sig2 = Signature.getInstance("SHA1withDSA", "SUN");
	    byte[] bytes = toCheck.getBytes();
	    sig2.initVerify(pk);
	    sig2.update(bytes, 0, bytes.length);
	    return sig2.verify(sig);
    }
}

class Sha256Hash{

    public static String convertBytesToHexString(byte[] bytes) {
		StringBuffer toReturn = new StringBuffer();
		for (int j = 0; j < bytes.length; j++) {
		    String hexit = String.format("%02x", bytes[j]);
		    toReturn.append(hexit);
		}
		return toReturn.toString();
    }

    public static String calculateHash(String x) {
		if (x == null) {
		    return "0";
		}
		byte[] hash = null;
		try {
		    MessageDigest digest = MessageDigest.getInstance("SHA-256");
		    hash = digest.digest(x.getBytes());
		} catch (NoSuchAlgorithmException nsaex) {
		    System.err.println("No SHA-256 algorithm found.");
		    System.err.println("This generally should not happen...");
		    System.exit(1);
		}
		return convertBytesToHexString(hash);
    }
}

// Block object with getters/setters
class block{

	String previousBlock, blockType, coinID, coinSignature, signature;

	public block(String[] block) {
		previousBlock = block[0];
		blockType = block[1];
		coinID = block[2];
		coinSignature = block[3];
		signature = block[4];
	}
	public String getPrevious(){
		return previousBlock;
	}
	public String getType(){
		return blockType;
	}
	public String getCoinID(){
		return coinID;
	}
	public String getCoinSig(){
		return coinSignature;
	}
	public String getSig(){
		return signature;
	}
	public String getLine(){
		return previousBlock + "," + blockType + "," + coinID + "," + coinSignature;
	}
	public String getEntireLine(){
		return getLine() + "," + signature;
	}
}