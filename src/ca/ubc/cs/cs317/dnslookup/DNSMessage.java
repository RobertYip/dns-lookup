package ca.ubc.cs.cs317.dnslookup;

//import com.sun.xml.internal.ws.util.StringUtils;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.stream.IntStream;

public class DNSMessage {
    public static final int MAX_DNS_MESSAGE_LENGTH = 512;

    // The offset into the message where the header ends and the data begins.
    public final static int DataOffset = 12;

    // Opcode for a standard query
    public final static int QUERY = 0;

    /**
     * Private Fields here
     */
    private final int HEADER_SIZE = 12;
    private final ByteBuffer buffer;

    private int qdcount;
    private int ancount;
    private int nscount;
    private int arcount;
    private final HashMap<String, Integer> hm = new HashMap<>();

    /**
     * Initializes an empty DNSMessage with the given id.
     *
     * @param id The id of the message.
     */

    public DNSMessage(short id) {
        this.buffer = ByteBuffer.allocate(MAX_DNS_MESSAGE_LENGTH);
        this.buffer.putShort(0, id);

        // set position to after header
        this.buffer.position(HEADER_SIZE);
        this.qdcount = 0;
        this.ancount = 0;
        this.nscount = 0;
        this.arcount = 0;
    }

    /**
     * Initializes a DNSMessage with the first length bytes of the given byte array.
     *
     * @param recvd  The byte array containing the received message
     * @param length The length of the data in the array
     */
    public DNSMessage(byte[] recvd, int length) {
        this.buffer = ByteBuffer.wrap(recvd, 0, length);
        // update position to after wrap
        this.buffer.position(HEADER_SIZE);
        this.qdcount = getQDCount();
        this.ancount = getANCount();
        this.nscount = getNSCount();
        this.arcount = getARCount();
    }

    /**
     * Getters and setters for the various fixed size and fixed location fields of a DNSMessage
     */
    public int getID() {
        return this.buffer.getShort(0) & 0x0000FFFF;
    }

    public void setID(int id) {
        this.buffer.putShort(0, (short) id);
    }

    public boolean getQR() {
        byte b = this.buffer.get(2);
        return (b & 0b10000000) >> 7 == 1;
    }

    public void setQR(boolean qr) {
        byte b = this.buffer.get(2);
        b = qr ? (byte) (b | 0b10000000) : (byte) (b & 0b01111111);
        this.buffer.put(2, b);
    }

    public boolean getAA() {
        byte b = this.buffer.get(2);
        return (b & 0b00000100) >> 2 == 1;
    }

    public void setAA(boolean aa) {
        byte b = this.buffer.get(2);
        b = aa ? (byte) (b | 0b00000100) : (byte) (b & 0b111111011);
        this.buffer.put(2, b);
    }

    public int getOpcode() {
        byte b = this.buffer.get(2);
        return (b & 0b01111000) >> 3;
    }

    public void setOpcode(int opcode) {
        byte b = this.buffer.get(2);
        // use mask to clear opcode bits to 0 before setting value
        b = (byte) ((byte) opcode << 3 | (b & 0b10000111));
        this.buffer.put(2, b);
    }

    public boolean getTC() {
        byte b = this.buffer.get(2);
        return (b & 0b00000010) >> 1 == 1;
    }

    public void setTC(boolean tc) {
        byte b = this.buffer.get(2);
        b = tc ? (byte) (b | 0b00000010) : (byte) (b & 0b11111101);
        this.buffer.put(2, b);
    }

    public boolean getRD() {
        byte b = this.buffer.get(2);
        return (b & 0b00000001) == 1;
    }

    public void setRD(boolean rd) {
        byte b = this.buffer.get(2);
        b = rd ? (byte) (b | 0b00000001) : (byte) (b & 0b11111110);
        this.buffer.put(2, b);
    }

    public boolean getRA() {
        byte b = this.buffer.get(3);
        return (b & 0b10000000) >> 7 == 1;
    }

    public void setRA(boolean ra) {
        byte b = this.buffer.get(3);
        b = ra ? (byte) (b | 0b10000000) : (byte) (b & 0b01111111);
        this.buffer.put(3, b);
    }

    public int getRcode() {
        byte b = this.buffer.get(3);
        return (b & 0b00001111);
    }

    public void setRcode(int rcode) {
        byte b = this.buffer.get(3);
        // use mask to clear rcode bits to 0 before setting value
        b = (byte) ((byte) rcode | (b & 0b11110000));
        this.buffer.put(3, b);
    }

    public int getQDCount() {
        return (int) this.buffer.getShort(4) & 0xFFFF;
    }

    public void setQDCount(int count) {
        this.buffer.putShort(4, (short) count);
    }

    public int getANCount() {
        return (int) this.buffer.getShort(6) & 0xFFFF;
    }

    public void setANCount(int count) {
        this.buffer.putShort(6, (short) count);
    }

    public int getNSCount() {
        return (int) this.buffer.getShort(8) & 0xFFFF;
    }

    public void setNSCount(int count) {
        this.buffer.putShort(8, (short) count);
    }

    public int getARCount() {
        return (int) this.buffer.getShort(10) & 0xFFFF;
    }

    public void setARCount(int count) {
        this.buffer.putShort(10, (short) count);
    }

    /**
     * Return the name at the current position() of the buffer.
     * <p>
     * The encoding of names in DNS messages is a bit tricky.
     * You should read section 4.1.4 of RFC 1035 very, very carefully.  Then you should draw a picture of
     * how some domain names might be encoded.  Once you have the data structure firmly in your mind, then
     * design the code to read names.
     *
     * @return The decoded name
     */
    public String getName() {
        String name = "";
        int currPos = this.buffer.position();
        int nextPos = 0;
        while (this.buffer.get(currPos) != 0) {
            if ((this.buffer.get(currPos) & 0b11000000) == 0b11000000) {
                // pointer condition: first bits (1, 1)
                if (nextPos == 0) {
                    nextPos = currPos + 2;
                }
                currPos = this.buffer.getShort(currPos) & 0x3FFF;
            }
            // default condition
            // get next numChar characters
            int numChar = this.buffer.get(currPos);

            // move to first char of name
            currPos++;

            for (int i = 0; i < numChar; i++) {
                name += (char) this.buffer.get(currPos + i);
            }
            name += ".";
            currPos += numChar;
        }

        // remove last "."
        if (!name.isEmpty()) {
            name = name.substring(0, name.length() - 1);
        }

        if (nextPos == 0) {
            this.buffer.position(currPos + 1);
        } else {
            this.buffer.position(nextPos);
        }

        return name;
    }

    /**
     * The standard toString method that displays everything in a message.
     *
     * @return The string representation of the message
     */
    public String toString() {
        // Remember the current position of the buffer so that we can put it back
        // Since toString() can be called by the debugger, we want to be careful to not change
        // the position in the buffer.  We remember what it was and put it back when we are done.
        int end = buffer.position();
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("ID: ").append(getID()).append(' ');
            sb.append("QR: ").append(getQR() ? "Response" : "Query").append(' ');
            sb.append("OP: ").append(getOpcode()).append(' ');
            sb.append("AA: ").append(getAA()).append('\n');
            sb.append("TC: ").append(getTC()).append(' ');
            sb.append("RD: ").append(getRD()).append(' ');
            sb.append("RA: ").append(getRA()).append(' ');
            sb.append("RCODE: ").append(getRcode()).append(' ')
                    .append(dnsErrorMessage(getRcode())).append('\n');
            sb.append("QDCount: ").append(getQDCount()).append(' ');
            sb.append("ANCount: ").append(getANCount()).append(' ');
            sb.append("NSCount: ").append(getNSCount()).append(' ');
            sb.append("ARCount: ").append(getARCount()).append('\n');
            buffer.position(DataOffset);
            showQuestions(getQDCount(), sb);
            showRRs("Authoritative", getANCount(), sb);
            showRRs("Name servers", getNSCount(), sb);
            showRRs("Additional", getARCount(), sb);
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "toString failed on DNSMessage";
        } finally {
            buffer.position(end);
        }
    }

    /**
     * Add the text representation of all the questions (there are nq of them) to the StringBuilder sb.
     *
     * @param nq Number of questions
     * @param sb Collects the string representations
     */
    private void showQuestions(int nq, StringBuilder sb) {
        sb.append("Question [").append(nq).append("]\n");
        for (int i = 0; i < nq; i++) {
            DNSQuestion question = getQuestion();
            sb.append('[').append(i).append(']').append(' ').append(question).append('\n');
        }
    }

    /**
     * Add the text representation of all the resource records (there are nrrs of them) to the StringBuilder sb.
     *
     * @param kind Label used to kind of resource record (which section are we looking at)
     * @param nrrs Number of resource records
     * @param sb   Collects the string representations
     */
    private void showRRs(String kind, int nrrs, StringBuilder sb) {
        sb.append(kind).append(" [").append(nrrs).append("]\n");
        for (int i = 0; i < nrrs; i++) {
            ResourceRecord rr = getRR();
            sb.append('[').append(i).append(']').append(' ').append(rr).append('\n');
        }
    }

    /**
     * Decode and return the question that appears next in the message.  The current position in the
     * buffer indicates where the question starts.
     *
     * @return The decoded question
     */
    public DNSQuestion getQuestion() {
        // name
        String hostname = this.getName();
        // rt
        RecordType rt = RecordType.getByCode(this.buffer.getShort());

        // rc
        RecordClass rc = RecordClass.getByCode(this.buffer.getShort());

        return new DNSQuestion(hostname, rt, rc);
    }

    /**
     * Decode and return the resource record that appears next in the message.  The current
     * position in the buffer indicates where the resource record starts.
     *
     * @return The decoded resource record
     */
    public ResourceRecord getRR() {
        String name = "";
        // ANSWER
        DNSQuestion answer = getQuestion();
        // TTL (signed 32-bit int)
        int ttl = this.buffer.getInt();

        // RDLENGTH not used; skip
        this.buffer.getShort();

        // RRDATA by type
        int type = answer.getRecordType().getCode();
        if (type == 2 || type == 5) {
            // NS, CNAME
            name = getName();
        } else if (type == 1) {
            // A
            int pos = this.buffer.position() - 1;

            for (int i = 0; i < 4; i++) {
                name += ((this.buffer.getShort(pos + i)) & 0xFF) + ".";
            }
            name = name.substring(0, name.length() - 1);
            InetAddress ip = null;
            try {
                ip = InetAddress.getByName(name);
            } catch (Exception e) {
                // do nothing for error, assume correct
            }
            this.buffer.position(this.buffer.position() + 4);

            return new ResourceRecord(answer, ttl, ip);
        } else if (type == 28) {
            // AAAA
            byte[] byteArray = new byte[2];
            for (int i = 0; i < 8; i++) {
                byteArray[0] = this.buffer.get();
                byteArray[1] = this.buffer.get();
                name += byteArrayToHexString(byteArray) + ":";
            }
            name = name.substring(0, name.length() - 1);
            InetAddress ip = null;
            try {
                ip = InetAddress.getByName(name);
            } catch (Exception e) {
                // do nothing for error, assume correct
            }
            return new ResourceRecord(answer, ttl, ip);
        } else if (type == 15) {
            // MX
            this.buffer.getShort(); // skip PREFERENCE short
            name = getName();
        } else {
            // Other types not implemented
        }

        return new ResourceRecord(answer, ttl, name);
    }

    /**
     * Helper function that returns a hex string representation of a byte array. May be used to represent the result of
     * records that are returned by a server but are not supported by the application (e.g., SOA records).
     *
     * @param data a byte array containing the record data.
     * @return A string containing the hex value of every byte in the data.
     */
    public static String byteArrayToHexString(byte[] data) {
        return IntStream.range(0, data.length).mapToObj(i -> String.format("%02x", data[i])).reduce("", String::concat);
    }

    /**
     * Helper function that returns a byte array from a hex string representation. May be used to represent the result of
     * records that are returned by a server but are not supported by the application (e.g., SOA records).
     *
     * @param hexString a string containing the hex value of every byte in the data.
     * @return data a byte array containing the record data.
     */
    public static byte[] hexStringToByteArray(String hexString) {
        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            String s = hexString.substring(i * 2, i * 2 + 2);
            bytes[i] = (byte) Integer.parseInt(s, 16);
        }
        return bytes;
    }

    /**
     * Add an encoded name to the message. It is added at the current position and uses compression
     * as much as possible.  Make sure you understand the compressed data format of DNS names.
     *
     * @param name The name to be added
     */
    public void addName(String name) {
        if (!name.isEmpty()) {
            // full match
            if (hm.get(name) != null) {
                int pos = hm.get(name);
                this.buffer.putShort((short) (pos | 0xc000));
                return;
            }

            hm.put(name, this.buffer.position());

            // insert first name element
            String[] nameArray = name.split("\\.");
            if (nameArray.length > 1) {
                int length = nameArray[0].length();
                this.buffer.put((byte) length);
                for (char c : nameArray[0].toCharArray()) {
                    this.buffer.put((byte) c);
                }

                //join back array
                String newName = "";
                for (int i = 1; i < nameArray.length; i++) {
                    newName += nameArray[i] + ".";
                }
                if (!newName.isEmpty()) {
                    newName = newName.substring(0, newName.length() - 1);
                }
                addName(newName);
            } else {
                // nameArray length == 1
                int length = name.length();
                this.buffer.put((byte) length);
                for (char c : name.toCharArray()) {
                    this.buffer.put((byte) c);
                }
                this.buffer.put((byte) 0);
            }
        }
    }

    /**
     * Add an encoded question to the message at the current position.
     *
     * @param question The question to be added
     */
    public void addQuestion(DNSQuestion question) {
        // DONE: Complete this method
        addName(question.getHostName());
        addQType(question.getRecordType());
        addQClass(question.getRecordClass());

        this.qdcount++;
        setQDCount(this.qdcount);
    }

    /**
     * Add an encoded resource record to the message at the current position.
     * The record is added to the additional records section.
     *
     * @param rr The resource record to be added
     */
    public void addResourceRecord(ResourceRecord rr) {
        addResourceRecord(rr, "additional");
    }

    /**
     * Add an encoded resource record to the message at the current position.
     *
     * @param rr      The resource record to be added
     * @param section Indicates the section to which the resource record is added.
     *                It is one of "answer", "nameserver", or "additional".
     */
    public void addResourceRecord(ResourceRecord rr, String section) {
        switch (section) {
            case "answer":
                this.ancount++;
                setANCount(this.ancount);
                break;
            case "nameserver":
                this.nscount++;
                setNSCount(this.nscount);
                break;
            case "additional":
                this.arcount++;
                setARCount(this.arcount);
                break;
            default:
                // no resource record, should not come here
                return;
        }

        // NAME, TYPE, CLASS
        addName(rr.getHostName());
        addQType(rr.getRecordType());
        addQClass(rr.getRecordClass());

        // TTL
        long ttl = rr.getRemainingTTL();
        this.buffer.putInt((int) ttl);

        // RDLENGTH (filler for now)
        this.buffer.putShort((short) 0);

        int rdataStartPos = this.buffer.position();

        int rtCode = rr.getRecordType().getCode();

        if (rtCode == 1) {
            // A
            String s = rr.getInetResult().getHostAddress();
            String[] sArray = s.split("\\.");
            for (String value : sArray) {
                this.buffer.put((byte) Integer.parseInt(value));
            }
        } else if (rtCode == 2 || rtCode == 5) {
            // NS, CNAME
            addName(rr.getTextResult());
        } else if (rtCode == 15) {
            // MX, PREFERENCE and EXCHANGE format
            this.buffer.putShort((short) 0);
            addName(rr.getTextResult());
        } else if (rtCode == 28) {
            // AAAA
            String ipv6 = rr.getInetResult().getHostAddress();
            String[] ipv6Array = ipv6.split(":");
            byte[] byteArray;
            for (String value : ipv6Array) {
                if (value.equals("") || value.equals("0")) {
                    // 0 or uncompressed
                    this.buffer.putShort((short) 0);
                } else {
                    // add 0 in the front until length is 4
                    String s = value;
                    for (int j = value.length(); j < 4; j++) {
                        s = "0" + s;
                    }
                    byteArray = hexStringToByteArray(s);
                    this.buffer.put(byteArray[0]);
                    this.buffer.put(byteArray[1]);
                }
            }
        } else {
            // SOA, OTHER
        }


        // calculate and add RDLENGTH
        int rdataEndPosPos = this.buffer.position();
        int textLengthInBytes = rdataEndPosPos - rdataStartPos;
        this.buffer.putShort(rdataStartPos - 2, (short) textLengthInBytes);
    }

    /**
     * Add an encoded type to the message at the current position.
     *
     * @param recordType The type to be added
     */
    private void addQType(RecordType recordType) {
        this.buffer.putShort((short) recordType.getCode());
    }

    /**
     * Add an encoded class to the message at the current position.
     *
     * @param recordClass The class to be added
     */
    private void addQClass(RecordClass recordClass) {
        this.buffer.putShort((short) recordClass.getCode());
    }

    /**
     * Return a byte array that contains all the data comprising this message.  The length of the
     * array will be exactly the same as the current position in the buffer.
     *
     * @return A byte array containing this message's data
     */
    public byte[] getUsed() {
        int length = this.buffer.position();
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            result[i] = this.buffer.get(i);
        }
        return result;
    }

    /**
     * Returns a string representation of a DNS error code.
     *
     * @param error The error code received from the server.
     * @return A string representation of the error code.
     */
    public static String dnsErrorMessage(int error) {
        final String[] errors = new String[]{
                "No error", // 0
                "Format error", // 1
                "Server failure", // 2
                "Name error (name does not exist)", // 3
                "Not implemented (parameters not supported)", // 4
                "Refused" // 5
        };
        if (error >= 0 && error < errors.length)
            return errors[error];
        return "Invalid error message";
    }

    public void getPos() {
        System.out.println("Position :" + this.buffer.position());
    }
}
