/*
 * based on https://github.com/stefano-lupo/Java-Proxy-Server
 */

package nl.clariah.ldproxy;

import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.KeyStore;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import javax.imageio.ImageIO;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import nl.clariah.ldproxy.recipe.Recipe;

public class RequestHandler implements Runnable {

	/**
	 * Socket connected to client passed by Proxy server
	 */
	Socket clientSocket;

	/**
	 * Read data client sends to proxy
	 */
	BufferedReader proxyToClientBr;

	/**
	 * Send data from proxy to client
	 */
	BufferedWriter proxyToClientBw;
	

	/**
	 * Thread that is used to transmit data read from client to server when using HTTPS
	 * Reference to this is required so it can be closed once completed.
	 */
	private Thread httpsClientToServer;


	/**
	 * Creates a ReuqestHandler object capable of servicing HTTP(S) GET requests
	 * @param clientSocket socket connected to the client
	 */
	public RequestHandler(Socket clientSocket){
		this.clientSocket = clientSocket;
		try{
			this.clientSocket.setSoTimeout(2000);
			proxyToClientBr = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
			proxyToClientBw = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
		} 
		catch (IOException e) {
			e.printStackTrace();
		}
	}


	
	/**
	 * Reads and examines the requestString and calls the appropriate method based 
	 * on the request type. 
	 */
	@Override
	public void run() {

            // Get Request from client
            String requestString;
            try{
                    requestString = proxyToClientBr.readLine();
            } catch (IOException e) {
                    System.err.println("!ERR: reading request from client: "+e.getMessage());
                    e.printStackTrace(System.err);
                    return;
            }
            if (requestString == null) {
                    System.err.println("!ERR: NULL request from client");
                    return;
            }

            // Parse out URL

            System.err.println("?DBG: Request Received " + requestString);
            // Get the Request type
            String request = requestString.substring(0,requestString.indexOf(' '));

            // remove request type and space
            String urlString = requestString.substring(requestString.indexOf(' ')+1);

            // Remove everything past next space
            urlString = urlString.substring(0, urlString.indexOf(' '));

            // Prepend http:// if necessary to create correct URL
            if(!urlString.substring(0,4).equals("http")){
                    String temp = "http://";
                    urlString = temp + urlString;
            }


            // Check request type
            if(request.equals("CONNECT")){
                    System.err.println("?DBG: HTTPS Request for : " + urlString + "\n");
                    // handleHTTPSRequest(urlString);
                    handleHTTPSRequest2(urlString);
            } else {
                Matcher m = null;
                for (Pattern p:Proxy.ldsites.keySet()) {
                        System.err.println("?DBG: site["+p+"]~["+urlString+"]? ");
                        m = p.matcher(urlString);
                        if (m.matches()) {
                                try {
                                        Recipe r = Proxy.ldsites.get(p);
                                        System.err.println("?DBG: LD Recipe["+r.getClass()+"] found for : " + urlString + "\n");
                                        BufferedReader reader = r.handle(proxyToClientBw,m);
                                        if(reader != null){
                                            String response = "HTTP/1.0 200 OK\n" +
                                            "Proxy-agent: LDProxy/1.0\n" +
                                            "\r\n";
                                            proxyToClientBw.write(response);
                                            proxyToClientBw.flush();
                                            String line;
                                            while((line = reader.readLine()) != null){
                                                    proxyToClientBw.write(line);
                                            }
                                            proxyToClientBw.flush();
                                            // Close resources
                                            reader.close();
                                        }	
                                        break;
                                } catch (IOException e) {
                                        System.err.println("!ERR: Sending LD recipe output file to client: "+e.getMessage());
                                        e.printStackTrace(System.err);
                                }
                        }
                }
                if (m==null || !m.matches()) {
                        System.err.println("?DBG: HTTP GET for : " + urlString + "\n");
                        sendNonCachedToClient(urlString);
                } else {
                    if (proxyToClientBw != null){
                        try {
                            proxyToClientBw.close();
                        } catch (IOException ex) {
                            System.err.println("!ERR: couldn't close connection to client: "+ex.getMessage());
                            ex.printStackTrace(System.err);
                        }
                    }
                }
            }
	} 


	/**
	 * Sends the contents of the file specified by the urlString to the client
	 * @param urlString URL of the file requested
	 */
	private void sendNonCachedToClient(String urlString){

		try{
			
			// Compute a logical file name as per schema
			// This allows the files on stored on disk to resemble that of the URL it was taken from
			int fileExtensionIndex = urlString.lastIndexOf(".");
			String fileExtension;

			// Get the type of file
			fileExtension = urlString.substring(fileExtensionIndex, urlString.length());

			// Trailing / result in index.html of that directory being fetched
			if(fileExtension.contains("/")){
				fileExtension = fileExtension.replace("/", "__");
				fileExtension = fileExtension.replace('.','_');
				fileExtension += ".html";
			}

			// Check if file is an image
			if((fileExtension.contains(".png")) || fileExtension.contains(".jpg") ||
					fileExtension.contains(".jpeg") || fileExtension.contains(".gif")){
				// Create the URL
				URL remoteURL = new URL(urlString);
				BufferedImage image = ImageIO.read(remoteURL);

				if(image != null) {
					// Send response code to client
					String line = "HTTP/1.0 200 OK\n" +
							"Proxy-agent: LDProxy/1.0\n" +
							"\r\n";
					proxyToClientBw.write(line);
					proxyToClientBw.flush();

					// Send them the image data
					ImageIO.write(image, fileExtension.substring(1), clientSocket.getOutputStream());

				// No image received from remote server
				} else {
					System.out.println("Sending 404 to client as image wasn't received from server");
					String error = "HTTP/1.0 404 NOT FOUND\n" +
							"Proxy-agent: LDProxy/1.0\n" +
							"\r\n";
					proxyToClientBw.write(error);
					proxyToClientBw.flush();
					return;
				}
			} 

			// File is a text file
			else {
								
				// Create the URL
				URL remoteURL = new URL(urlString);
				// Create a connection to remote server
				HttpURLConnection proxyToServerCon = (HttpURLConnection)remoteURL.openConnection();
				proxyToServerCon.setRequestProperty("Content-Type", 
						"application/x-www-form-urlencoded");
				proxyToServerCon.setRequestProperty("Content-Language", "en-US");  
				proxyToServerCon.setUseCaches(false);
				proxyToServerCon.setDoOutput(true);
			
				// Create Buffered Reader from remote Server
				BufferedReader proxyToServerBR = new BufferedReader(new InputStreamReader(proxyToServerCon.getInputStream()));
				

				// Send success code to client
				String line = "HTTP/1.0 200 OK\n" +
						"Proxy-agent: LDProxy/1.0\n" +
						"\r\n";
				proxyToClientBw.write(line);
				
				
				// Read from input stream between proxy and remote server
				while((line = proxyToServerBR.readLine()) != null){
					// Send on data to client
					proxyToClientBw.write(line);

				}
				
				// Ensure all data is sent by this point
				proxyToClientBw.flush();

				// Close Down Resources
				if(proxyToServerBR != null){
					proxyToServerBR.close();
				}
			}



			if(proxyToClientBw != null){
				proxyToClientBw.close();
			}
		} 

		catch (Exception e){
			e.printStackTrace();
		}
	}

	
	/**
	 * Handles HTTPS requests between client and remote server
	 * @param urlString desired file to be transmitted over https
	 */
	private void handleHTTPSRequest(String urlString){
		// Extract the URL and port of remote 
		String url = urlString.substring(7);
		String pieces[] = url.split(":");
		url = pieces[0];
		int port  = Integer.valueOf(pieces[1]);

		try{
			// Only first line of HTTPS request has been read at this point (CONNECT *)
			// Read (and throw away) the rest of the initial data on the stream
			for(int i=0;i<5;i++){
				proxyToClientBr.readLine();
			}

			// Get actual IP associated with this URL through DNS
			InetAddress address = InetAddress.getByName(url);
			
			// Open a socket to the remote server 
			Socket proxyToServerSocket = new Socket(address, port);
			proxyToServerSocket.setSoTimeout(5000);

			// Send Connection established to the client
			String line = "HTTP/1.0 200 Connection established\r\n" +
					"Proxy-Agent: LDProxy/1.0\r\n" +
					"\r\n";
			proxyToClientBw.write(line);
			proxyToClientBw.flush();
			
			// Client and Remote will both start sending data to proxy at this point
			// Proxy needs to asynchronously read data from each party and send it to the other party
            sync(proxyToServerSocket);
		} catch (SocketTimeoutException e) {
			String line = "HTTP/1.0 504 Timeout Occured after 10s\n" +
					"User-Agent: LDProxy/1.0\n" +
					"\r\n";
			try{
				proxyToClientBw.write(line);
				proxyToClientBw.flush();
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
		} 
		catch (Exception e){
			System.out.println("Error on HTTPS : " + urlString );
			e.printStackTrace();
		}
	}

    private void handleHTTPSRequest2(String urlString) {
        try {
            // Extract the URL and port of remote
            String url = urlString.substring(7);
            String[] pieces = url.split(":");
            url = pieces[0];
            int port = Integer.parseInt(pieces[1]);

            // Only first line of HTTPS request has been read at this point (CONNECT *)
            // Read (and throw away) the rest of the initial data on the stream
            for (int i = 0; i < 5; i++) {
                proxyToClientBr.readLine();
            }

            // Let's open a secure connection to the server
            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, null, null);
            SSLSocket serverSocket = (SSLSocket) sslContext.getSocketFactory().createSocket(url, port);
            serverSocket.startHandshake();

            // Obtain information of the server's certificate we need for our certificate with the client
            X509Certificate[] certificates = (X509Certificate[]) serverSocket.getSession().getPeerCertificates();
            Principal serverDN = certificates[0].getSubjectX500Principal();
            BigInteger serverSerialNumber = certificates[0].getSerialNumber();

            // Create a forged certificate and a key manager factory and trust manager factory with the forged certificate
            KeyStore keyStore = CertificateBuilder.createForgedCertificateFor(serverDN, serverSerialNumber);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, new char[]{});
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);

            // Set up a secure connection with the client
            SSLContext ssl = SSLContext.getInstance("SSL");
            ssl.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
            ServerSocket localProxy = ssl.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getByName("localhost"));
            Socket sslProxySocket = ssl.getSocketFactory().createSocket("localhost", localProxy.getLocalPort());

            // Transfer all data from the client socket to the secured client proxy and vice versa
            new Thread(new ClientToServerHttpsTransmit(
                    clientSocket.getInputStream(),
                    sslProxySocket.getOutputStream())
            ).start();

            new Thread(new ClientToServerHttpsTransmit(
                    sslProxySocket.getInputStream(),
                    clientSocket.getOutputStream())
            ).start();

            // Send Connection established to the client
            String line = "HTTP/1.0 200 Connection established\r\n" +
                    "Proxy-Agent: LDProxy/1.0\r\n" +
                    "\r\n";
            proxyToClientBw.write(line);
            proxyToClientBw.flush();

			// Client and Remote will both start sending data to proxy at this point
			// Proxy needs to asynchronously read data from each party and send it to the other party
			clientSocket = localProxy.accept();
			sync(serverSocket);
        } catch (Exception e) {
            System.out.println("Error on HTTPS : " + urlString);
            e.printStackTrace();
        }
    }

    private void sync(Socket proxyToServerSocket) throws IOException {
        //Create a Buffered Writer betwen proxy and remote
        BufferedWriter proxyToServerBW = new BufferedWriter(new OutputStreamWriter(proxyToServerSocket.getOutputStream()));

        // Create Buffered Reader from proxy and remote
        BufferedReader proxyToServerBR = new BufferedReader(new InputStreamReader(proxyToServerSocket.getInputStream()));

        // Create a new thread to listen to client and transmit to server
        ClientToServerHttpsTransmit clientToServerHttps =
                new ClientToServerHttpsTransmit(clientSocket.getInputStream(), proxyToServerSocket.getOutputStream());

        httpsClientToServer = new Thread(clientToServerHttps);
        httpsClientToServer.start();

        // Listen to remote server and relay to client
        try {
            byte[] buffer = new byte[4096];
            int read;
            do {
                read = proxyToServerSocket.getInputStream().read(buffer);
                if (read > 0) {
                    clientSocket.getOutputStream().write(buffer, 0, read);
                    if (proxyToServerSocket.getInputStream().available() < 1) {
                        clientSocket.getOutputStream().flush();
                    }
                }
            } while (read >= 0);
        } catch (SocketTimeoutException e) {

        } catch (IOException e) {
            e.printStackTrace();
        }


        // Close Down Resources
        if (proxyToServerSocket != null) {
            proxyToServerSocket.close();
        }

        if (proxyToServerBR != null) {
            proxyToServerBR.close();
        }

        if (proxyToServerBW != null) {
            proxyToServerBW.close();
        }

        if (proxyToClientBw != null) {
            proxyToClientBw.close();
        }
    }


	/**
	 * Listen to data from client and transmits it to server.
	 * This is done on a separate thread as must be done 
	 * asynchronously to reading data from server and transmitting 
	 * that data to the client. 
	 */
	class ClientToServerHttpsTransmit implements Runnable{
		
		InputStream proxyToClientIS;
		OutputStream proxyToServerOS;
		
		/**
		 * Creates Object to Listen to Client and Transmit that data to the server
		 * @param proxyToClientIS Stream that proxy uses to receive data from client
		 * @param proxyToServerOS Stream that proxy uses to transmit data to remote server
		 */
		public ClientToServerHttpsTransmit(InputStream proxyToClientIS, OutputStream proxyToServerOS) {
			this.proxyToClientIS = proxyToClientIS;
			this.proxyToServerOS = proxyToServerOS;
		}

		@Override
		public void run(){
			try {
				// Read byte by byte from client and send directly to server
				byte[] buffer = new byte[4096];
				int read;
				do {
					read = proxyToClientIS.read(buffer);
					if (read > 0) {
						proxyToServerOS.write(buffer, 0, read);
						if (proxyToClientIS.available() < 1) {
							proxyToServerOS.flush();
						}
					}
				} while (read >= 0);
			}
			catch (SocketTimeoutException ste) {
				// TODO: handle exception
			}
			catch (IOException e) {
				System.out.println("Proxy to client HTTPS read timed out");
				e.printStackTrace();
			}
		}
	}

	
}




