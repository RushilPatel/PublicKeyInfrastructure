package org.pki.dto;

public class SocketMessage {

    private boolean isError;
    private byte[] data;

    public SocketMessage(boolean isError, byte[] data){
        this.data = data;
        this.isError = isError;
    }

    public boolean isError() {
        return isError;
    }


    public byte[] getData() {
        return data;
    }

    public int getDataLength(){
        return data.length;
    }
}
