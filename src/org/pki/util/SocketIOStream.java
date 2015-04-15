package org.pki.util;

import org.pki.dto.SocketMessage;

import java.io.*;

public class SocketIOStream {

    private DataOutputStream outputStream;
    private DataInputStream inputStream;

    public SocketIOStream(InputStream inputStream, OutputStream outputStream){
        this.outputStream = new DataOutputStream(outputStream);
        this.inputStream = new DataInputStream(inputStream);
    }

    public void sendMessage(SocketMessage message) throws IOException{
        outputStream.writeBoolean(message.isError());
        outputStream.writeInt(message.getDataLength());
        outputStream.write(message.getData());
        outputStream.flush();
    }

    public SocketMessage readMessage() throws IOException{
        boolean isError = inputStream.readBoolean();
        int messageLength = inputStream.readInt();
        byte [] data = new byte[messageLength];
        inputStream.readFully(data);
        return new SocketMessage(isError, data);
    }

    public void close() throws IOException{
        this.inputStream.close();
        this.outputStream.close();
    }
}
