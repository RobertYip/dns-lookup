package ca.ubc.cs.cs317.dnslookup;

import java.io.IOException;
import java.net.*;
import java.util.*;

public class DNSLookupService {

    public static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL_NS = 10;
    private static final int MAX_QUERY_ATTEMPTS = 3;
    private static final int MAX_DNS_MESSAGE_LENGTH = 512;
    private static final int SO_TIMEOUT = 5000;

    private final DNSCache cache = DNSCache.getInstance();
    private final Random random = new Random();
    private final DNSVerbosePrinter verbose;
    private final DatagramSocket socket;


    /**
     * Creates a new lookup service. Also initializes the datagram socket object with a default timeout.
     *
     * @param verbose A DNSVerbosePrinter listener object with methods to be called at key events in the query
     *                processing.
     * @throws SocketException      If a DatagramSocket cannot be created.
     * @throws UnknownHostException If the nameserver is not a valid server.
     */
    public DNSLookupService(DNSVerbosePrinter verbose) throws SocketException, UnknownHostException {
        this.verbose = verbose;
        socket = new DatagramSocket();
        socket.setSoTimeout(SO_TIMEOUT);
    }

    /**
     * Closes the lookup service and related sockets and resources.
     */
    public void close() {
        socket.close();
    }

    /**
     * Examines a set of resource records to see if any of them are an answer to the given question.
     *
     * @param rrs      The set of resource records to be examined
     * @param question The DNS question
     * @return true if the collection of resource records contains an answer to the given question.
     */
    private boolean containsAnswer(Collection<ResourceRecord> rrs, DNSQuestion question) {
        for (ResourceRecord rr : rrs) {
            if (rr.getQuestion().equals(question) && rr.getRecordType() == question.getRecordType()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Finds all the results for a specific question. If there are valid (not expired) results in the cache, uses these
     * results, otherwise queries the nameserver for new records. If there are CNAME records associated to the question,
     * they are retrieved recursively for new records of the same type, and the returning set will contain both the
     * CNAME record and the resulting resource records of the indicated type.
     *
     * @param question             Host and record type to be used for search.
     * @param maxIndirectionLevels Number of CNAME indirection levels to support.
     * @return A set of resource records corresponding to the specific query requested.
     * @throws DNSErrorException If the number CNAME redirection levels exceeds the value set in
     *                           maxIndirectionLevels.
     */
    public Collection<ResourceRecord> getResultsFollowingCNames(DNSQuestion question, int maxIndirectionLevels)
            throws DNSErrorException {

        if (maxIndirectionLevels < 0) throw new DNSErrorException("CNAME indirection limit exceeded");

        Collection<ResourceRecord> directResults = iterativeQuery(question);
        if (containsAnswer(directResults, question)) {
            return directResults;
        }

        Set<ResourceRecord> newResults = new HashSet<>();
        for (ResourceRecord record : directResults) {
            newResults.add(record);
            if (record.getRecordType() == RecordType.CNAME) {
                newResults.addAll(getResultsFollowingCNames(
                        new DNSQuestion(record.getTextResult(), question.getRecordType(), question.getRecordClass()),
                        maxIndirectionLevels - 1));
            }
        }
        return newResults;
    }

    /**
     * Answers one question.  If there are valid (not expired) results in the cache, returns these results.
     * Otherwise it chooses the best nameserver to query, retrieves results from that server
     * (using individualQueryProcess which adds all the results to the cache) and repeats until either:
     * the cache contains an answer to the query, or
     * the cache contains an answer to the query that is a CNAME record rather than the requested type, or
     * every "best" nameserver in the cache has already been tried.
     *
     * @param question Host name and record type/class to be used for the query.
     */
    public Collection<ResourceRecord> iterativeQuery(DNSQuestion question)
            throws DNSErrorException {
        Set<ResourceRecord> ans = new HashSet<>();
        // Available in cache
        Collection<ResourceRecord> cacheResults = cache.getCachedResults(question);
        if (cacheResults.size() > 0) return cacheResults;

        // Query rootserver
        InetAddress server = null;
        Set<InetAddress> tried = new HashSet<>();
        List<ResourceRecord> serverList = cache.getBestNameservers(question);
        Set<ResourceRecord> serversNotTried = new HashSet<>();

        // use first server
        String strServer = serverList.get(0).getTextResult();
        DNSQuestion serverQuestion = new DNSQuestion(strServer, RecordType.A, RecordClass.IN);
        Collection<ResourceRecord> rootServerList = cache.getCachedResults(serverQuestion);
        server = rootServerList.iterator().next().getInetResult();
        // Iterate servers
        while (serverList.size() >= 0) {
            if (serverList.size() == 0){
                if (serversNotTried.size() > 0) {
                    serverList.addAll(serversNotTried);
                    serversNotTried.clear();
                    continue;
                } else{
                    return ans;
                }
            }
            for (ResourceRecord rr : serverList){
                cache.addResult(rr);
            }
            cacheResults = cache.getCachedResults(question);
            if (cacheResults.size() > 0) return cacheResults;

            ResourceRecord currServer = serverList.remove(0);

            //cname
            if (currServer.getRecordType() == RecordType.CNAME) {
                ans.add(currServer);
                DNSQuestion q = new DNSQuestion(currServer.getTextResult(), question.getRecordType(), question.getRecordClass());
                Collection<ResourceRecord> cnameList = iterativeQuery(q);
                for (ResourceRecord rr : cnameList) {
                    ans.add(rr);
                }
                return ans;
            }

            if (currServer.getRecordType() == RecordType.A) {
                server = currServer.getInetResult();
            } else if (currServer.getRecordType() == RecordType.NS) {
                String nextServer = currServer.getTextResult();
                DNSQuestion q = new DNSQuestion(nextServer, RecordType.A, RecordClass.IN);
                Collection<ResourceRecord> nextServerList = cache.getCachedResults(q);
                if (nextServerList.isEmpty()) {
                    nextServerList = iterativeQuery(q);
                }
                if (nextServerList.isEmpty()) continue;
                server = nextServerList.iterator().next().getInetResult();
            }
            if (tried.contains(server)) continue;
            tried.add(server);

            Set<ResourceRecord> nextServers = individualQueryProcess(question, server);
            if (nextServers.size() > 0) {
                serversNotTried.addAll(serverList);
                serverList = cache.getBestNameservers(question);
            }
        }
        return ans;
    }

    /**
     * Handles the process of sending an individual DNS query with a single question. Builds and sends the query (request)
     * message, then receives and parses the response. Received responses that do not match the requested transaction ID
     * are ignored. If no response is received after SO_TIMEOUT milliseconds, the request is sent again, with the same
     * transaction ID. The query should be sent at most MAX_QUERY_ATTEMPTS times, after which the function should return
     * without changing any values. If a response is received, all of its records are added to the cache.
     * <p>
     * If the reply contains a non-zero Rcode value, then throw a DNSErrorException.
     * <p>
     * The method verbose.printQueryToSend() must be called every time a new query message is about to be sent.
     *
     * @param question Host name and record type/class to be used for the query.
     * @param server   Address of the server to be used for the query.
     * @return If no response is received, returns null. Otherwise, returns a set of all resource records
     * received in the response.
     * @throws DNSErrorException if the Rcode in the response is non-zero
     */
    public Set<ResourceRecord> individualQueryProcess(DNSQuestion question, InetAddress server)
            throws DNSErrorException {
        int attemptNumber = MAX_QUERY_ATTEMPTS;

        /* Build and Send */
        DNSMessage responseMsg;
        DatagramPacket packet = null;
        DNSMessage reqMsg = buildQuery(question);
        byte[] reqMsgBuf = reqMsg.getUsed();

        try {
            verbose.printQueryToSend(question, server, reqMsg.getID());
            packet = new DatagramPacket(reqMsgBuf, reqMsgBuf.length, server, DEFAULT_DNS_PORT);
            socket.send(packet);
            // allocate space and receive
            while (attemptNumber > 0) {
                byte[] buf = new byte[512];
                packet = new DatagramPacket(buf, buf.length);
                try {
                    socket.receive(packet);
                    byte[] data = packet.getData();
                    int dataLength = packet.getLength();
                    responseMsg = new DNSMessage(data, dataLength);
                    if (responseMsg.getRcode() != 0)
                        throw new DNSErrorException("R-code is " + responseMsg.getRcode());

                    if (responseMsg.getQR() && responseMsg.getID() == reqMsg.getID()) {
                        Set<ResourceRecord> responses = processResponse(responseMsg);
                        return responses;
                    }
                } catch (SocketTimeoutException e) {
                    verbose.printQueryToSend(question, server, reqMsg.getID());
                    packet = new DatagramPacket(reqMsgBuf, reqMsgBuf.length, server, DEFAULT_DNS_PORT);
                    socket.send(packet);
                    attemptNumber--;
                }
            }
        } catch (IOException e) {
            // for socket.send()
        }
        return null;
    }

    /**
     * Creates a DNSMessage containing a DNS query.
     * A random transaction ID must be generated and filled in the corresponding part of the query. The query
     * must be built as an iterative (non-recursive) request for a regular query with a single question. When the
     * function returns, the message's buffer's position (`message.buffer.position`) must be equivalent
     * to the size of the query data.
     *
     * @param question Host name and record type/class to be used for the query.
     * @return The DNSMessage containing the query.
     */
    public DNSMessage buildQuery(DNSQuestion question) {
        short randomId = (short) random.nextInt(65536);
        DNSMessage message = new DNSMessage(randomId);
        message.setQR(false); // this message is a query
        message.addQuestion(question);
        assert message.getUsed().length == message.buffer.position();
        return message;
    }

    /**
     * Parses and processes a response received by a nameserver.
     * If the reply contains a non-zero Rcode value, then throw a DNSErrorException.
     * Adds all resource records found in the response message to the cache.
     * Calls methods in the verbose object at appropriate points of the processing sequence. Must be able
     * to properly parse records of the types: A, AAAA, NS, CNAME and MX (the priority field for MX may be ignored). Any
     * other unsupported record type must create a record object with the data represented as a hex string (see method
     * byteArrayToHexString).
     *
     * @param message The DNSMessage received from the server.
     * @return A set of all resource records received in the response.
     * @throws DNSErrorException if the Rcode value in the reply header is non-zero
     */
    public Set<ResourceRecord> processResponse(DNSMessage message) throws DNSErrorException {
        if (message.getRcode() != 0) throw new DNSErrorException("R-code is " + message.getRcode());
        int id = message.getID();
        boolean aa = message.getAA();
        int errorCode = message.getOpcode();
        verbose.printResponseHeaderInfo(id, aa, errorCode);
        Set<ResourceRecord> ans = new HashSet<>();
        try {
            DNSQuestion q = message.getQuestion();
            int anCount = message.getANCount();
            verbose.printAnswersHeader(anCount);
            while (anCount > 0) {
                ResourceRecord rr = message.getRR();
                verbose.printIndividualResourceRecord(rr, rr.getRecordType().getCode(), rr.getRecordClass().getCode());
                ans.add(rr);
                cache.addResult(rr);
                anCount--;
            }

            int nsCount = message.getNSCount();
            verbose.printNameserversHeader(nsCount);
            while (nsCount > 0) {
                ResourceRecord rr = message.getRR();
                verbose.printIndividualResourceRecord(rr, rr.getRecordType().getCode(), rr.getRecordClass().getCode());
                ans.add(rr);
                cache.addResult(rr);
                nsCount--;
            }

            int arCount = message.getARCount();
            verbose.printAdditionalInfoHeader(arCount);
            while (arCount > 0) {
                ResourceRecord rr = message.getRR();
                verbose.printIndividualResourceRecord(rr, rr.getRecordType().getCode(), rr.getRecordClass().getCode());
                ans.add(rr);
                cache.addResult(rr);
                arCount--;
            }

        } catch (Exception e) {
            // break
            // include out of bounds for message.getRR
        }
        return ans;
    }

    public static class DNSErrorException extends Exception {
        public DNSErrorException(String msg) {
            super(msg);
        }
    }
}