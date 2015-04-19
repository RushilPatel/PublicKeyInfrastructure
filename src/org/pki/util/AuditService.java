package org.pki.util;


import java.io.*;

public class AuditService {
    private static AuditService auditService;
    private DataOutputStream auditStream;

    private AuditService() throws FileNotFoundException{
        this.auditStream = new DataOutputStream(new FileOutputStream(new File("audit.log")));
    }

    /**
     * Singleton object
     * @return - auditing server
     */
    public static AuditService getAuditService(){
        try{
            if(auditService == null){
                auditService = new AuditService();
            }
            return auditService;
        }catch (FileNotFoundException e){
            System.out.println("Cannot create auditing");
            return null;
        }
    }

    /**
     * log message to file
     * @param message - message to write to file
     */
    public synchronized void log(String message){
        if(auditService == null){
            return;
        }
        try{
            this.auditStream.writeBytes(message + "\n");
            this.auditStream.flush();
        }catch (IOException e){
        }

    }
}
