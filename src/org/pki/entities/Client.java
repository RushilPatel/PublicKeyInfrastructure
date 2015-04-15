package org.pki.entities;

import java.io.IOException;
import java.net.Socket;

public class Client implements Runnable{

    @Override
    public void run() {
        try{
            Socket socket = new Socket("localhost", 7777);

        }catch (IOException e){
            e.printStackTrace();
        }

    }
}
