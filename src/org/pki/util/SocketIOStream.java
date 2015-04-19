package org.pki.util;

import org.pki.dto.SocketMessage;

import java.io.*;

/**
 * Handle data transfer on socket
 */
public class SocketIOStream {

    private DataOutputStream outputStream;
    private DataInputStream inputStream;

    /**
     * Create stream using sockets streams
     * @param inputStream - socket input stream
     * @param outputStream - socket output sream
     */
    public SocketIOStream(InputStream inputStream, OutputStream outputStream){
        this.outputStream = new DataOutputStream(outputStream);
        this.inputStream = new DataInputStream(inputStream);
    }

    /**
     * Send message on socket
     * @param message - socket message object to send
     * @throws IOException
     */
    public void sendMessage(SocketMessage message) throws IOException{
        outputStream.writeBoolean(message.isError()); //write the type of message
        outputStream.writeInt(message.getDataLength()); //write the length of data
        outputStream.write(message.getData()); //write data
        outputStream.flush(); //flush stream
    }

    /**
     * Read message from socket
     * @throws IOException
     */
    public SocketMessage readMessage() throws IOException{
        boolean isError = inputStream.readBoolean(); //read message type
        int messageLength = inputStream.readInt(); //read length of data
        byte [] data = new byte[messageLength];
        inputStream.readFully(data); //read data
        return new SocketMessage(isError, data); //create object to wrap message
    }

    /**
     * Closes input and output streams
     * @throws IOException
     */
    public void close() throws IOException{
        this.inputStream.close();
        this.outputStream.close();
    }
}
