package com.example.apiBook.service;

import com.amazonaws.util.IOUtils;
import org.apache.commons.net.ftp.FTP;
import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPReply;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;

@Service
public class FtpService implements CommandLineRunner, ApplicationListener<ContextClosedEvent> {

    private static final String SERVER_ADDRESS = "172.24.55.161";
    private static final int SERVER_PORT = 21;
    private static final int FTP_TIMEOUT = 60000;
    private static final String USERNAME = "hungdz";
    private static final String PASSWORD = "1";
    private FTPClient ftpClient;
    private int reply;
    String ftpPath;

    public void uploadFile(MultipartFile file, String fileName) throws IOException {
        connectFTPServer();
        System.out.println("ftpPath: " + ftpPath + fileName);
        InputStream inputStream = file.getInputStream();
        boolean success = ftpClient.storeFile(fileName, inputStream);
        disconnectFTPServer();
    }

    public byte[] retrieveFile(String fileName) throws IOException {
        connectFTPServer();
        System.out.println("ftpPath: "+ ftpClient.printWorkingDirectory());
        InputStream inputStream = ftpClient.retrieveFileStream(ftpPath +"/"+ fileName);
        System.out.println("input Stream" + inputStream);
        byte[] fileContent = IOUtils.toByteArray(inputStream);
        disconnectFTPServer();
        return fileContent;
    }

    private void connectFTPServer() throws IOException {
        ftpClient = new FTPClient();
        try {
            System.out.println("connecting ftp server...");
            ftpClient.connect(SERVER_ADDRESS, SERVER_PORT);
            ftpClient.login(USERNAME, PASSWORD);
            ftpClient.enterLocalPassiveMode();
            reply = ftpClient.getReplyCode();
            if (!FTPReply.isPositiveCompletion(reply)) {
                ftpClient.disconnect();
                throw new IOException("FTP server not respond!");
            } else {
                System.out.println("connected");
                ftpClient.setFileType(FTP.BINARY_FILE_TYPE);
                ftpPath = ftpClient.printWorkingDirectory();
                ftpClient.setDataTimeout(FTP_TIMEOUT);
            }
            // check reply code

        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    @Override
    public void onApplicationEvent(ContextClosedEvent event) {
        disconnectFTPServer();
    }

    @Override
    public void run(String... args) throws Exception {
        connectFTPServer();
    }


    /**
     * disconnect ftp server
     *
     * @author viettuts.vn
     */
    private void disconnectFTPServer() {
        if (ftpClient != null && ftpClient.isConnected()) {
            try {
                ftpClient.logout();
                ftpClient.disconnect();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

}