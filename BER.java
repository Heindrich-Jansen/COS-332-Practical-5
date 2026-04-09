import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class BER {

	public static final int TAG_CLASS_UNIVERSAL = 0x00;
	public static final int TAG_CLASS_APPLICATION = 0x40;
	public static final int TAG_CLASS_CONTEXT = 0x80;
	public static final int TAG_CLASS_PRIVATE = 0xC0;

	public static final int TAG_BOOLEAN = 0x01;
	public static final int TAG_INTEGER = 0x02;
	public static final int TAG_OCTET_STRING = 0x04;
	public static final int TAG_SEQUENCE = 0x10;

	public static final class BerValue {
		public final int tagClass;
		public final boolean constructed;
		public final int tagNumber;
		public final byte[] value;

		public BerValue(int tagClass, boolean constructed, int tagNumber, byte[] value) {
			this.tagClass = tagClass;
			this.constructed = constructed;
			this.tagNumber = tagNumber;
			this.value = value;
		}

		public boolean isUniversal(int tag) {
			return tagClass == TAG_CLASS_UNIVERSAL && tagNumber == tag;
		}

		public long asInteger() throws IOException {
			if (!isUniversal(TAG_INTEGER)) {
				throw new IOException("BER value is not an integer");
			}
			if (value.length == 0) {
				throw new IOException("Empty integer value");
			}

			long result = 0;
			for (byte b : value) {
				result = (result << 8) | (b & 0xFFL);
			}

			if ((value[0] & 0x80) != 0 && value.length < Long.BYTES) {
				long signMask = -1L << (value.length * 8);
				result |= signMask;
			}

			return result;
		}

		public boolean asBoolean() throws IOException {
			if (!isUniversal(TAG_BOOLEAN)) {
				throw new IOException("BER value is not a boolean");
			}
			return value.length > 0 && value[0] != 0x00;
		}

		public String asString() throws IOException {
			if (!isUniversal(TAG_OCTET_STRING)) {
				throw new IOException("BER value is not an octet string");
			}
			return new String(value, StandardCharsets.UTF_8);
		}

		public List<BerValue> asSequence() throws IOException {
			if (!constructed) {
				throw new IOException("BER value is not constructed");
			}
			return BER.decodeAll(new ByteArrayInputStream(value));
		}
	}

	public static BerValue decode(InputStream input) throws IOException {
		int firstTagByte = input.read();
		if (firstTagByte < 0) {
			throw new EOFException("No BER value available");
		}

		int tagClass = firstTagByte & 0xC0;
		boolean constructed = (firstTagByte & 0x20) != 0;
		int tagNumber = firstTagByte & 0x1F;
		if (tagNumber == 0x1F) {
			throw new IOException("High-tag-number form is not supported in this minimal BER outline");
		}

		int length = readLength(input);
		byte[] value = readFully(input, length);
		return new BerValue(tagClass, constructed, tagNumber, value);
	}

	public static BerValue decodeSingle(byte[] data) throws IOException {
		return decode(new ByteArrayInputStream(data));
	}

	public static List<BerValue> decodeAll(InputStream input) throws IOException {
		List<BerValue> values = new ArrayList<>();
		while (true) {
			input.mark(1);
			int next = input.read();
			if (next < 0) {
				break;
			}
			input.reset();
			values.add(decode(input));
		}
		return values;
	}

	public static byte[] encodeInteger(long value) throws IOException {
		ByteArrayOutputStream content = new ByteArrayOutputStream();

		if (value == 0) {
			content.write(0x00);
		} else {
			ArrayList<Byte> bytes = new ArrayList<>();
			long current = value;
			while (current != 0 && current != -1) {
				bytes.add(0, (byte) (current & 0xFF));
				current >>= 8;
			}

			if (bytes.isEmpty()) {
				bytes.add((byte) 0x00);
			}

			if (value > 0 && (bytes.get(0) & 0x80) != 0) {
				bytes.add(0, (byte) 0x00);
			}
			if (value < 0 && (bytes.get(0) & 0x80) == 0) {
				bytes.add(0, (byte) 0xFF);
			}

			for (byte b : bytes) {
				content.write(b);
			}
		}

		return encodeUniversal(TAG_INTEGER, false, content.toByteArray());
	}

	public static byte[] encodeBoolean(boolean value) throws IOException {
		return encodeUniversal(TAG_BOOLEAN, false, new byte[] { (byte) (value ? 0xFF : 0x00) });
	}

	public static byte[] encodeOctetString(String value) throws IOException {
		return encodeOctetString(value.getBytes(StandardCharsets.UTF_8));
	}

	public static byte[] encodeOctetString(byte[] value) throws IOException {
		return encodeUniversal(TAG_OCTET_STRING, false, value);
	}

	public static byte[] encodeSequence(List<byte[]> encodedChildren) throws IOException {
		ByteArrayOutputStream content = new ByteArrayOutputStream();
		for (byte[] child : encodedChildren) {
			content.write(child);
		}
		return encodeUniversal(TAG_SEQUENCE, true, content.toByteArray());
	}

	public static byte[] encodeApplication(int tagNumber, boolean constructed, byte[] value) throws IOException {
		return encodeTagged(TAG_CLASS_APPLICATION, constructed, tagNumber, value);
	}

	public static byte[] encodeContextSpecific(int tagNumber, boolean constructed, byte[] value) throws IOException {
		return encodeTagged(TAG_CLASS_CONTEXT, constructed, tagNumber, value);
	}

	public static byte[] encodeTagged(int tagClass, boolean constructed, int tagNumber, byte[] value) throws IOException {
		if (tagNumber < 0 || tagNumber > 30) {
			throw new IOException("This minimal BER outline only supports low tag numbers (0-30)");
		}

		ByteArrayOutputStream output = new ByteArrayOutputStream();
		output.write(tagClass | (constructed ? 0x20 : 0x00) | tagNumber);
		writeLength(output, value.length);
		output.write(value);
		return output.toByteArray();
	}

	private static byte[] encodeUniversal(int tagNumber, boolean constructed, byte[] value) throws IOException {
		return encodeTagged(TAG_CLASS_UNIVERSAL, constructed, tagNumber, value);
	}

	private static int readLength(InputStream input) throws IOException {
		int first = input.read();
		if (first < 0) {
			throw new EOFException("Unexpected end of BER length");
		}

		if ((first & 0x80) == 0) {
			return first;
		}

		int count = first & 0x7F;
		if (count == 0) {
			throw new IOException("Indefinite length is not supported in this minimal BER outline");
		}

		int length = 0;
		for (int i = 0; i < count; i++) {
			int next = input.read();
			if (next < 0) {
				throw new EOFException("Unexpected end of BER length bytes");
			}
			length = (length << 8) | next;
		}
		return length;
	}

	private static void writeLength(ByteArrayOutputStream output, int length) {
		if (length < 0x80) {
			output.write(length);
			return;
		}

		byte[] buffer = new byte[4];
		int count = 0;
		int remaining = length;
		while (remaining > 0) {
			buffer[buffer.length - 1 - count] = (byte) (remaining & 0xFF);
			remaining >>= 8;
			count++;
		}

		output.write(0x80 | count);
		for (int i = buffer.length - count; i < buffer.length; i++) {
			output.write(buffer[i]);
		}
	}

	private static byte[] readFully(InputStream input, int length) throws IOException {
		byte[] data = new byte[length];
		int offset = 0;
		while (offset < length) {
			int read = input.read(data, offset, length - offset);
			if (read < 0) {
				throw new EOFException("Unexpected end of BER value");
			}
			offset += read;
		}
		return data;
	}

	public static void main(String[] args) throws Exception {
		byte[] encoded = BER.encodeSequence(List.of(
				BER.encodeInteger(5),
				BER.encodeBoolean(true),
				BER.encodeOctetString("ldap")
		));

		BerValue decoded = BER.decodeSingle(encoded);
		System.out.println("Outer tag class: " + decoded.tagClass);
		System.out.println("Outer tag number: " + decoded.tagNumber);
		System.out.println("Children: " + decoded.asSequence().size());
	}
}
