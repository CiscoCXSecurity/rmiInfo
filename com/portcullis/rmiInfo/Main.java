/*
 * Main.java
 *
 * Created on May 23, 2007, 5:21 PM
 * By James Fisher
 *
 * 
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */
package com.portcullis.rmiInfo;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import java.util.Vector;

/**
 *
 * @author james
 */
public class Main
{

    private static String version = "0.3";
    private static Main main;
    static int[] requestInitial = {0x4a, 0x52, 0x4d, 0x49, 0x00, 0x02, 0x4b};
    static int[] requestGetServices = {0x00, 0x09, 0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x00, 0x00, 0x00, 0x00, 0x50, 0xac, 0xed, 0x00, 0x05, 0x77, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x44, 0x15, 0x4d, 0xc9, 0xd4, 0xe6, 0x3b, 223};
    static int[] requestGetServiceInfo = {0x50, 0xac, 0xed, 0x00, 0x05, 0x77, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x44, 0x15, 0x4d, 0xc9, 0xd4, 0xe6, 0x3b, 0xdf, 0x74, 0x00};

    /** Creates a new instance of Main */
    private Main()
    {

    }

    public static Main getInstance()
    {
        if (main == null)
        {
            main = new Main();
        }

        return main;
    }

    private static void printinfo()
    {
        System.out.println("rmiInfo " + version);
        System.out.println("Home page: http://labs.portcullis.co.uk/application/rmiInfo/");
        System.out.println("Written by: James Fisher");
        System.out.println("Contact: jpf@portcullis-security.com");
        System.out.println("License: GPLv3");
        System.out.println();
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args)
    {
        main = Main.getInstance();
        if (args.length != 2)
        {
            printinfo();
            System.out.println("Usage");
            System.out.println("\t java - jar rmiInfo-" + version + ".jar <ipaddress> <port>");
            System.exit(0);
        }
        try
        {
            printinfo();
            System.out.println("Running......");
            System.out.println();
            processService(args[0], Integer.parseInt(args[1]), null);
            System.out.println("Finished");
        }
        catch (NumberFormatException ex)
        {
            ex.printStackTrace();
        }
        catch (UnknownHostException ex)
        {
            ex.printStackTrace();
        }
        catch (IOException ex)
        {
            ex.printStackTrace();
        }
    }

    private static void processService(String serviceAddress, int port, String stubname) throws NumberFormatException, UnknownHostException, IOException
    {
        try
        {
            /*
             * Vector to store all the services found
             */

            Vector service = new Vector(10, 10);

            Socket s = new Socket(serviceAddress, port);
            InputStream in = s.getInputStream();

            OutputStream out = s.getOutputStream();

            /*
             * Send the opening hand shake
             */

            sendIntArray(out, requestInitial);

            Vector responceInitial = getResponce(in);

            /*
             * test if we have an rmiregistry responce
             */

            if (((Integer) responceInitial.elementAt(0)).intValue() != 78 || ((Integer) responceInitial.elementAt(1)).intValue() != 0)
            {
                System.out.println("Failed to get a vaild rmi responce");
                System.out.println("Sorry it didn't work out");
                System.exit(0);
            }

            int tempin;
            Vector byteIn = new Vector(100, 10);



            /*
             * Get the names of all the registered services
             */

            sendIntArray(out, requestGetServices);

            Vector responceGetServices = getResponce(in);

            /*
             * Try to work out what we are looking at
             */

            if (((Integer) responceGetServices.elementAt(7)).intValue() == 1)
            {
                /*
                 * We are looking at a RMI registry
                 */

                System.out.println("Found a RMI registry");
                System.out.println("------------------------");


                int numberOfElements = ((Integer) responceGetServices.elementAt(62)).intValue();

                System.out.println("Number of rmi services discoverd: " + numberOfElements);

                int start = 62;
                for (int b = 0; b < numberOfElements; b++)
                {

                    int length = ((Integer) responceGetServices.elementAt(start + 3)).intValue();

                    int stringStart = start + 4;
                    int stringEnd = stringStart + length - 1;

                    StringBuffer sb = new StringBuffer();
                    for (int pointer = stringStart; pointer <= stringEnd; pointer++)
                    {
                        sb.append((char) ((Integer) responceGetServices.elementAt(pointer)).intValue());
                    }
                    System.out.println("RMI service discovered: " + sb.toString());
                    service.addElement(sb.toString());
                    start = stringEnd;
                }

                /*
                 * get the location and stub name of all the services
                 */

                for (int b = 0; b < service.size(); b++)
                {
                    String serviceName = (String) service.elementAt(b);

                    System.out.println();
                    System.out.println("Extracting information for service: " + serviceName);
                    System.out.println("Name: " + serviceName);

                    /*
                     * send the intial part of the request
                     */
                    sendIntArray(out, requestGetServiceInfo);

                    /*
                     * add the length of name
                     */
                    out.write(serviceName.length());

                    /*
                     * send the service name 
                     */

                    for (int c = 0; c < serviceName.length(); c++)
                    {
                        out.write((int) serviceName.charAt(c));
                    }

                    out.flush();

                    Vector responceGetServiceInfo = getResponce(in);

                    /*
                     * Get the length of the stub
                     */
                    int stublength = ((Integer) responceGetServiceInfo.elementAt(25)).intValue();


                    /*
                     * Get the stub name
                     */
                    StringBuffer sb = new StringBuffer();
                    for (int pointer = 26; pointer < 26 + stublength; pointer++)
                    {

                        sb.append((char) ((Integer) responceGetServiceInfo.elementAt(pointer)).intValue());
                    }

                    String stubName = sb.toString();

                    /*
                     * Reset the stringbuffer
                     */
                    sb = new StringBuffer();

                    System.out.println("Stub name: " + stubName);


                    /*
                     * Get the length of the address the service is bound to
                     */
                    int addressLength = ((Integer) responceGetServiceInfo.elementAt(26 + stublength + 115)).intValue();

                    /*
                     * Get the address
                     */
                    for (int pointer = 26 + stublength + 116; pointer < 26 + stublength + 116 + addressLength; pointer++)
                    {

                        sb.append((char) ((Integer) responceGetServiceInfo.elementAt(pointer)).intValue());
                    }


                    String address = serviceAddress;

                    System.out.println("address: " + address);

                    /*
                     * Get the port number of the service
                     */
                    int portPart1 = ((Integer) responceGetServiceInfo.elementAt(26 + stublength + 116 + addressLength + 2)).intValue();
                    int portPart2 = ((Integer) responceGetServiceInfo.elementAt(26 + stublength + 116 + addressLength + 3)).intValue();

                    /*
                     * Calc the port number from it's hex value
                     */
                    int portNumber = (portPart1 * (16 * 16)) + portPart2;

                    System.out.println("port: " + portNumber);


                    /*
                     * raw packet dump
                     */
                    System.out.println("<Raw packet dump>");

                    for (int d = 0; d < responceGetServiceInfo.size(); d++)
                    {
                        int temp = ((Integer) responceGetServiceInfo.elementAt(d)).intValue();

                        /*
                         * raw packet dump
                         */

                        System.out.print((char) temp);
                    }
                    System.out.print("\n");
                    System.out.println("</Raw packet dump>");
                    System.out.println();

                    /*
                     * Now process all the RMI service that we have found
                     */
                    System.out.println("Investigating rmi service");
                    System.out.println("Connecting to " + address + ":" + portNumber + " ........");
                    processService(address, portNumber, stubName);
                }

                out.close();
                in.close();
                s.close();
            }
            else if (((Integer) responceGetServices.elementAt(7)).intValue() == 2)
            {
                /*
                 * We are looking at a RMI service
                 */

                System.out.println("Found an RMI service");
                System.out.println("Trying to find remote stub location.....");

                StringBuffer sb = new StringBuffer();
                for (int a = 0; a < responceGetServices.size(); a++)
                {
                    sb.append((char) ((Integer) responceGetServices.elementAt(a)).intValue());
                }

                if (((Integer) responceGetServices.elementAt(67)).intValue() == 116 && ((Integer) responceGetServices.elementAt(68)).intValue() == 0)
                {
                    int locLength = ((Integer) responceGetServices.elementAt(69)).intValue();

                    StringBuffer sb2 = new StringBuffer();

                    for (int b = 70; b < 70 + locLength; b++)
                    {
                        sb2.append((char) ((Integer) responceGetServices.elementAt(b)).intValue());
                    }
                    System.out.println("Found possible location of stub: " + sb2.toString() + stubname + ".class");
                    System.out.println("<Raw packet dump>");
                    System.out.println(sb.toString());
                    System.out.println("</Raw packet dump>");
                }
                else
                {
                    System.out.println("Could not determine location of possible remote stub");
                    System.out.println("<Raw packet dump>");
                    System.out.println(sb.toString());
                    System.out.println("</Raw packet dump>");
                }

                System.out.println();

            }
            else
            {
                /*
                 * We are looking at something else
                 */

                StringBuffer sb = new StringBuffer();
                for (int a = 0; a < responceGetServices.size(); a++)
                {

                    sb.append((char) ((Integer) responceGetServices.elementAt(a)).intValue());
                }

                System.out.println("Got an unexpected result printing packet dump");
                System.out.println("<Raw packet dump>");
                System.out.println(sb.toString());
                System.out.println("</Raw packet dump>");

            }
        }
        catch (ConnectException e)
        {
            System.out.println("Connection time out!");
        }
    }

    private static void sendIntArray(OutputStream out, int[] data) throws IOException
    {
        for (int count = 0; count < data.length; count++)
        {
            out.write(data[count]);
            out.flush();
        }
    }

    private static Vector getResponce(InputStream in) throws IOException
    {
        int tempin = 0;
        Vector byteIn = new Vector(100, 10);

        while ((tempin = in.read()) != -1 && in.available() > 0)
        {

            byteIn.addElement(new Integer(tempin));

        }
        byteIn.addElement(new Integer(tempin));
        tempin = 0;


        /*
         * debug code to print what is found
         */
        /*
        StringBuffer sb = new StringBuffer();
        for (int a = 0; a < byteIn.size(); a++)
        {
        sb.append((char) ((Integer) byteIn.elementAt(a)).intValue());
        }
        //System.out.println("item = " + sb.toString());
        System.out.println("Got an unexpected result");
        System.out.println("------------------------");
        System.out.println(sb.toString());
        System.out.println("------------------------");
         */
        return byteIn;
    }
}
