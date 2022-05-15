/*
 * Chat.onion - P2P Instant Messenger
 *
 * http://play.google.com/store/apps/details?id=onion.chat
 * http://onionapps.github.io/Chat.onion/
 * http://github.com/onionApps/Chat.onion
 *
 * Author: http://github.com/onionApps - http://jkrnk73uid7p5thz.onion - bitcoin:1kGXfWx8PHZEVriCNkbP5hzD15HS4AyKf
 */

package com.ivor.coatex.tor;

import static java.lang.System.arraycopy;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import com.ivor.coatex.utils.Util;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA3Digest;



import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Tor {

    private static String torname = "ctor";
    private static String tordirname = "tordata";
    private static String torservdir = "torserv";
    private static String torCfg = "torcfg";
    private static int HIDDEN_SERVICE_VERSION = 3;
    private static Tor instance = null;
    private Context mContext;
    private static int mSocksPort = 9151;
    private static int mHttpPort = 8191;
    private String mDomain = "";
    private ArrayList<Listener> mListeners;
    private ArrayList<LogListener> mLogListeners;
    private String status = "";
    private boolean mReady = false;

    private File mTorDir;

    private Process mProcessTor;

    private AtomicBoolean mRunning = new AtomicBoolean(false);

    private Tor(Context c) {

        this.mContext = c;

        mListeners = new ArrayList<>();
        mLogListeners = new ArrayList<>();

        mTorDir = new File(c.getFilesDir(), "tor");
        if (!mTorDir.exists()) {
            mTorDir.mkdir();
        }

        mDomain = Util.filestr(new File(getServiceDir(), "hostname")).trim();
        log(mDomain);
    }

    /**
     * start the tor thread
     */
    public void start() {
        if (mRunning.get()) return; // if already running, don't do anything

        Server.getInstance(mContext).setServiceRegistered(false);
        mReady = false;
        new Thread() {
            @Override
            public void run() {
                try {
                    test();
                    // log("kill");
                    // Native.killTor();

                    // log("install");
                    // extractFile(mContext, R.raw.tor, torname);

                    //log("delete on exit");
                    //context.getFileStreamPath(torname).deleteOnExit();

                    // log("set executable");
                    // mContext.getFileStreamPath(torname).setExecutable(true);

                    log("make dir");
                    File tordir = new File(mTorDir, tordirname);
                    tordir.mkdirs();

                    log("make service");
                    File torsrv = new File(mTorDir, torservdir);
                    torsrv.mkdirs();

                    log("configure");
                    PrintWriter torcfg = new PrintWriter(mContext.openFileOutput(torCfg, Context.MODE_PRIVATE));
                    //torcfg.println("Log debug stdout");
//                    torcfg.println("Log notice stdout");
                    torcfg.println("DataDirectory " + tordir.getAbsolutePath());
                    torcfg.println("SOCKSPort " + mSocksPort);
                    torcfg.println("HTTPTunnelPort " + mHttpPort);
                    torcfg.println("HiddenServiceDir " + torsrv.getAbsolutePath());
                    torcfg.println("HiddenServiceVersion " + HIDDEN_SERVICE_VERSION);
                    torcfg.println("HiddenServicePort " + getHiddenServicePort() + " " + Server.getInstance(mContext).getSocketName());
                    torcfg.println("HiddenServicePort " + getFileServerPort() + " 127.0.0.1:" + getFileServerPort());
                    torcfg.println();
                    torcfg.close();
                    log(Util.filestr(new File(mContext.getFilesDir(), torCfg)));

                    log("start: " + new File(torname).getAbsolutePath());

                    // String[] command = new String[]{
                    //        mContext.getFileStreamPath(torname).getAbsolutePath(),
                    //        "-f", mContext.getFileStreamPath(torCfg).getAbsolutePath()
                    //};

                    //StringBuilder sb = new StringBuilder();
                    //for (String s : command) {
                    //    sb.append(s);
                    //    sb.append(" ");
                    //}

                    // log("Command: " + sb.toString());

                    mRunning.set(true);
                    String dir = mContext.getApplicationInfo().nativeLibraryDir;
                    log(dir);

                    Process tor;
                    mProcessTor = new ProcessBuilder().directory(new File(dir)).command("./libtor.so", "-f", mContext.getFileStreamPath("torcfg").getAbsolutePath()).redirectErrorStream(true).start();

                    // mProcessTor = Runtime.getRuntime().exec(command);
                    BufferedReader torReader = new BufferedReader(new InputStreamReader(mProcessTor.getInputStream()));
                    while (true) {
                        final String line = torReader.readLine();
                        if (line == null) break;
                        log(line);
                        status = line;

                        boolean ready2 = mReady;

                        if (line.contains("100%")) {
                            ls(mTorDir);
                            mDomain = Util.filestr(new File(torsrv, "hostname")).trim();
                            log(mDomain);
                            try {
                                for (Listener l : mListeners) {
                                    if (l != null) l.onChange();
                                }
                            } catch (Exception e) {
                            }
                            ready2 = true;

                            Server.getInstance(mContext).checkServiceRegistered();
                        }
                        mReady = ready2;
                        try {
                            for (LogListener ll : mLogListeners) {
                                if (ll != null) {
                                    ll.onLog();
                                }
                            }
                        } catch (Exception e) {

                        }
                    }
                } catch (Exception ex) {
                    ex.printStackTrace();
                    //throw new Error(ex);
                }
                mRunning.set(false);
            }
        }.start();
    }

    public static Tor getInstance(Context context) {
        if (instance == null) {
            instance = new Tor(context.getApplicationContext());
        }
        return instance;
    }

    static String computeID(byte[] pubkey) {
        // RSAPublicKeyStructure myKey = new RSAPublicKeyStructure(pubkey.getModulus(), pubkey.getPublicExponent());

        Digest digest = new SHA3Digest(256);
        byte[] label = ".onion checksum".getBytes(Charset.forName("US-ASCII"));
        digest.update(label, 0, label.length);
        digest.update(pubkey, 0, pubkey.length);
        digest.update((byte) 3); // ONION_HS_PROTOCOL_VERSION
        byte[] checksum = new byte[digest.getDigestSize()];
        digest.doFinal(checksum, 0);
        byte[] address = new byte[pubkey.length + 2 + 1]; // 2 = ONION_CHECKSUM_BYTES
        arraycopy(pubkey, 0, address, 0, pubkey.length);
        arraycopy(checksum, 0, address, pubkey.length, 2); // 2 = ONION_CHECKSUM_BYTES
        address[address.length - 1] = 3; // ONION_HS_PROTOCOL_VERSION
        return new Base32().encode(address).toString();
    }

    public static int getHiddenServicePort() {
        return 31512;
    }

    public static int getFileServerPort() {
        return 8088;
    }

    private void log(String s) {
        Log.d("Tor", "Data: " + s);
    }

    void ls(File f) {
        log(f.toString());
        if (f.isDirectory()) {
            for (File s : f.listFiles()) {
                ls(s);
            }
        }
    }

    public static int getSocksPort() {
        return mSocksPort;
    }

    public static int getHttpPort() {
        return mHttpPort;
    }

    public String getOnion() { return mDomain.trim(); }

    public String getID() {
        return mDomain.replace(".onion", "").trim();
    }

    public void addListener(Listener l) {
        if (l != null && !mListeners.contains(l)) {
            mListeners.add(l);
            l.onChange();
        }
    }

    public void removeListener(Listener l) {
        mListeners.remove(l);
    }

    private void extractFile(Context context, int id, String name) {
        try {
            InputStream i = context.getResources().openRawResource(id);
            OutputStream o = context.openFileOutput(name, Context.MODE_PRIVATE);
            int read;
            byte[] buffer = new byte[4096];
            while ((read = i.read(buffer)) > 0) {
                o.write(buffer, 0, read);
            }
            i.close();
            o.close();
        } catch (Exception ex) {
            ex.printStackTrace();
            //throw new Error(ex);
        }
    }

    public File getServiceDir() {
        return new File(mTorDir, torservdir);
    }

    private KeyFactory getKeyFactory() {
        if (Security.getProvider("EdDSA") == null) {
            Security.addProvider(new EdDSASecurityProvider());
        }
        try {
            return KeyFactory.getInstance("EdDSA", "EdDSA");
        } catch (Exception ex) {
            throw new Error(ex);
        }
    }
    private static byte[] sha512(byte[] input) {
        MessageDigest mDigest = null;
        try {
            mDigest = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] result = mDigest.digest(input);
        return result;
    }
    //public String readPrivateKeyFile() {
    //    return Util.filestr(new File(getServiceDir(), HIDDEN_SERVICE_VERSION == 3 ? "hs_ed25519_secret_key" : "private_key"));
    //}
    private static final EdDSANamedCurveSpec CURVE_SPEC =
            EdDSANamedCurveTable.getByName("Ed25519");

    public byte[] readPrivateKeyFile() {
        byte[] full1 = Util.filebin(new File(getServiceDir(), "hs_ed25519_secret_key"));
        byte[] full2 = Arrays.copyOfRange(full1, 32, 64);
        //log("full1: "+full1);
        //String full = full1.replace("== ed25519v1-secret: type0 ==\00\00\00", "");
        //log("full2: "+full);


        Base32 b32 = new Base32();
        // byte[] full3 = b32.encode(full2);


        //byte[] fullb = full.getBytes();


        // EdDSAPrivateKey pkey = new EdDSAPrivateKey(new EdDSAPrivateKeySpec(full3, CURVE_SPEC));
        // byte[] hash = sha512(Arrays.copyOfRange(pkey.getEncoded(), 0, 32));
        // hash[0] &= 248;
        // hash[31] &= 127;
        // hash[31] |= 64;


        log(CURVE_SPEC.toString());
        log(String.valueOf(CURVE_SPEC.getCurve().getField().getb()));
        log(String.valueOf(full1.length));
        log(String.valueOf(full2.length));
        //log(String.valueOf(full3.length));
        //log(pkey.toString());
        //return pkey.getEncoded();
        return full2;
    }

    public Ed25519PrivateKeyParameters getPrivateKey() {
        return new Ed25519PrivateKeyParameters(readPrivateKeyFile(), 0);
        //byte[] priv = readPrivateKeyFile();
        //log(priv);
        //priv = priv.replace("-----BEGIN RSA PRIVATE KEY-----\n", "");
        //priv = priv.replace("-----END RSA PRIVATE KEY-----", "");
        //priv = priv.replaceAll("\\s", "");
        //log(priv);
        // byte[] data = priv.getBytes(StandardCharsets.UTF_8);
        //log("" + data.length);
        // EdDSAPrivateKeySpec keySpec = new EdDSAPrivateKeySpec(priv, CURVE_SPEC);
        //log(keySpec.toString());
        //try {
        //    return (EdDSAPrivateKey) getKeyFactory().generatePrivate(keySpec);
        //} catch (InvalidKeySpecException ex) {
        //    throw new Error(ex);
        //}
    }

    //private EdDSAPrivateKeySpec getPrivateKeySpec() {
    //    try {
    //        return getKeyFactory().getKeySpec(getPrivateKey(), EdDSAPrivateKeySpec.class);
    //    } catch (InvalidKeySpecException ex) {
    //        throw new Error(ex);
    //    }
    //}

    //private EdDSAPublicKeySpec getPublicKeySpec() {
    //    return new EdDSAPublicKeySpec(getPrivateKeySpec().getSeed(), CURVE_SPEC);
   // }

    public Ed25519PublicKeyParameters getPublicKey() {
        // byte[] priv = readPrivateKeyFile();
        // EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(priv, CURVE_SPEC);
        // EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(privKey.getA(), CURVE_SPEC);
        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(readPrivateKeyFile(), 0);

        return privateKey.generatePublicKey();
    }

    private String computeOnion() {
        return computeID(getPublicKey().getEncoded()) + ".onion";
    }

    //public byte[] getPubKeySpec() {
    //    return getPrivateKeySpec().getModulus().toByteArray();
    //}
    //EdDSAPublicKeySpec getPubKeySpec() {
    //    return new EdDSAPublicKeySpec(getPrivateKeySpec().getSeed(), CURVE_SPEC);
    //}

    public byte[] pubkey() {
        // return Util.filebin(new File(getServiceDir(), "hs_ed25519_public_key"));
        log("pubkey: "+getPublicKey().getEncoded());
        return getPublicKey().getEncoded();
    }

    public byte[] sign(byte[] msg) {
        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(readPrivateKeyFile(), 0);

        Signer signer = new Ed25519Signer();
        signer.init(true, privateKey);
        signer.update(msg, 0, msg.length);
        try {
            byte[] signature = signer.generateSignature();
            return signature;
        } catch (CryptoException e) {
            e.printStackTrace();
        }
        log("sign(): failed!");
        return "".getBytes();
        //try {
        //    EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        //    Signature signature = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        //    //Signature signature = Signature.getInstance("SHA3withEdDSA");
        //    signature.initSign(getPrivateKey());
        //    signature.update(msg);
        //    return signature.sign();
        //} catch (Exception ex) {
        //    throw new Error(ex);
        //}
    }

    public void stop() {
        if (mProcessTor != null) mProcessTor.destroy();
    }

    public String encryptByPublicKey(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchProviderException {
        // Cipher encrypt;
        // if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.M) {
        //     encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        // } else {
        //     encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        // }
        // encrypt.init(Cipher.ENCRYPT_MODE, getPublicKey());
        // return AdvancedCrypto.toHex(encrypt.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        log("encryptByPublicKey: Not encrypted, sorry.");
        return data;
    }

    public String encryptByPublicKey(String data, byte[] pubKeySpecBytes) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException, NoSuchProviderException {
        // RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(pubKeySpecBytes), BigInteger.valueOf(65537));
        // PublicKey publicKey = getKeyFactory().generatePublic(publicKeySpec);

        // Cipher encrypt;
        // if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.M) {
        //    encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        //} else {
        //    encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        //}
        //encrypt.init(Cipher.ENCRYPT_MODE, publicKey);
        //return AdvancedCrypto.toHex(encrypt.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        log("encryptByPublicKey: Not encrypted, sorry.");
        return data;
    }

    public String decryptByPrivateKey(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchProviderException {
        // Cipher decrypt;
        // if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.M) {
        //     decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        // } else {
        //     decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        // }
        // decrypt.init(Cipher.DECRYPT_MODE, getPrivateKey());
        // return new String(decrypt.doFinal(AdvancedCrypto.toByte(data)), StandardCharsets.UTF_8);
        return data;
    }

    //public PublicKey convertKeySpec(byte[] pubkey) {
    //    RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(pubkey), BigInteger.valueOf(65537));
    //    PublicKey publicKey;
    //    try {
    //        publicKey = getKeyFactory().generatePublic(publicKeySpec);
    //    } catch (InvalidKeySpecException ex) {
    //        ex.printStackTrace();
    //        return null;
    //    }
    //    return publicKey;
    //}

    boolean checkSig(String id, byte[] pubkey, byte[] sig, byte[] msg) {

        Signer verifier = new Ed25519Signer();
        Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(pubkey, 0);
        verifier.init(false, publicKey);
        verifier.update(msg, 0, msg.length);
        boolean verified = verifier.verifySignature(sig);
        log("checkSig(): pubkey: "+pubkey.toString());
        log("checkSig(): publicKey: "+publicKey.getEncoded().toString());
        log("checkSig(): sig: "+sig.toString());
        log("checkSig(): msg: "+msg.toString());
        log("checkSig(): verified: "+verified);

        return verified;
        // return true;
        // RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(pubkey), BigInteger.valueOf(65537));

        //if (!id.equals(computeID(pubkey))) {
        //    log("invalid id");
        //    log("id: "+id);
        //    log("computeID(pubkey): "+ computeID(pubkey));
        //    log("pubkey: "+pubkey.toString());
        //    return false;
        //}
        // TODO: critical.
        //return true;
        //PublicKey publicKey;
        //try {
        //    publicKey = getKeyFactory().generatePublic(pubkey);
        //} catch (InvalidKeySpecException ex) {
        //    ex.printStackTrace();
        //    return false;
        //}
        //
        //try {
        //    Signature signature = Signature.getInstance("NONEwithEdDSA");
        //    signature.initVerify(publicKey);
        //    signature.update(msg);
        //    return signature.verify(sig);
        //} catch (Exception ex) {
        //    ex.printStackTrace();
        //    return false;
        // }
    }

    void test() {
        try {
            log("==================== T E S T ====================");

            String domain = Util.filestr(new File(getServiceDir(), "hostname")).trim();

            log(Util.filestr(new File(getServiceDir(), "hostname")).trim());
            log(computeID(getPublicKey().getEncoded()));
            log(computeOnion());
            log(Util.filestr(new File(getServiceDir(), "hostname")).trim());

            log(Base64.encodeToString(pubkey(), Base64.DEFAULT));
            log("= pub " + Base64.encodeToString(pubkey(), Base64.DEFAULT));

            byte[] msg = "alkjdalwkdjaw".getBytes();
            log("= msg " + Base64.encodeToString(msg, Base64.DEFAULT));

            byte[] sig = sign(msg);
            log("= sig " + Base64.encodeToString(sig, Base64.DEFAULT));

            log("= chk " + checkSig(getID(), pubkey(), sig, msg));

            log("===================== E N D =====================");
            // System.exit(0);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public void addLogListener(LogListener l) {
        if (!mLogListeners.contains(l)) {
            mLogListeners.add(l);
        }
    }

    public String getStatus() {
        return status;
    }

    public boolean isReady() {
        return mReady;
    }

    public void removeLogListener(LogListener ll) {
        mLogListeners.remove(ll);
    }

    public interface Listener {
        void onChange();
    }

    public interface LogListener {
        void onLog();
    }
}
