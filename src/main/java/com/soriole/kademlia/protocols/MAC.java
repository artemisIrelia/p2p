package com.soriole.kademlia.protocols;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MAC {

    SecretKeySpec signKey;
    Mac mac;

    public void init(String password, String algoMAC) throws NoSuchAlgorithmException, InvalidKeyException{
        //Generate Secret key from user key
        signKey = new SecretKeySpec(password.getBytes(), algoMAC);
        //Get mac instance
        mac = Mac.getInstance(algoMAC);
        //Init mac
        mac.init(signKey);

    }

    //generate MAC
    public byte[] giveMeMAC(String password, String message, String algoMAC){
        try {
            //Initialize the MAC with Key
            init(password, algoMAC);
            //Compute MAC
            return ( mac.doFinal(message.getBytes()));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MAC.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MAC.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}