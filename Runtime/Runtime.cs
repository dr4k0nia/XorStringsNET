using System.Text;

namespace Runtime;

public static unsafe class Runtime
{
    private struct Data
    {
        // Placeholder struct for data storage
    }

    public static string Decrypt(int id)
    {
        if (id >> 31 != 0) // shifting a negative number by 31 will result in -1 every other number will result in 0
            return string.Empty;

        // Placeholder for pointer to the struct
        byte* data = (byte*) 0x420;

        // Add decrypted index to the base pointer of the struct
        //data += (*&id & ~*(int*) data) | (~*&id & *(int*) data); // Equivalent to: *&id ^ *(int*) data
        data += id ^ *(int*) data;

        // Create a buffer to hold the encrypted string data
        // Use the length field of our format to initialize the buffer with the correct size
        byte[] buffer = new byte[*(int*) data];

        // Copy the encrypted bytes into the buffer
        fixed (void* ptr = &buffer[0])
        {
            // We need to add 8 to the pointer because 4 bytes are reserved for the length and another 4 bytes for the XOR key
            cpblk(ptr, data + 8, (uint) buffer.Length);
        }

        int n = buffer.Length - 1;
        for (int i = 0; i < n; i++, n--)
        {
            buffer[i] ^= buffer[n];
            buffer[n] ^= (byte)(buffer[i] ^ *(int*) (data + 4));
            buffer[i] ^= buffer[n];
        }
        if (buffer.Length % 2 != 0)
            buffer[buffer.Length >> 1] ^= (byte)*(int*) (data + 4); // x >> 1 == x / 2


        // Return the decrypted string as UTF8
        return string.Intern(Encoding.UTF8.GetString(buffer));
    }

    // Placeholder for cpblk
    private static void cpblk(void* destination, void* source, uint bytes)
    {
        throw new NotImplementedException();
    }
}
