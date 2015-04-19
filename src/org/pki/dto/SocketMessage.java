package org.pki.dto;

/**
 * Data transfer object to wrap data transferred on socket
 */
public class SocketMessage {

    private boolean isError;
    private byte[] data;

    /**
     * @param isError - sending error message
     * @param data - data to send
     */
    public SocketMessage(boolean isError, byte[] data){
        this.data = data;
        this.isError = isError;
    }

    /**
     * Message type
     * @return - is it as error message?
     */
    public boolean isError() {
        return isError;
    }

    /**
     * @return - message data
     */
    public byte[] getData() {
        return data;
    }

    /**
     * @return - length of message
     */
    public int getDataLength(){
        return data.length;
    }

    public String toString(){
        StringBuilder sb = new StringBuilder();
        sb.append("BEGINNING OF MESSAGE\n");
        sb.append("Is Error: " + this.isError());
        sb.append("\nLength: " + this.getData().length);
        sb.append("\nData: " + new String(this.getData()));
        sb.append("\nEND OF MESSAGE");
        return sb.toString();
    }
}
