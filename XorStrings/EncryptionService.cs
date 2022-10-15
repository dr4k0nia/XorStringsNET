using System.Security.Cryptography;
using System.Text;

namespace SimpleStringEncryption;

public class EncryptionService
{
    private readonly List<byte> _encryptedData;

    private readonly int _globalKey;

    private int _index;

    public EncryptionService()
    {
        _encryptedData = new List<byte>();
        _globalKey = RandomNumberGenerator.GetInt32(int.MaxValue);
        _encryptedData.AddRange(BitConverter.GetBytes(_globalKey));
        _index = 4;
    }

    public int Index => _index ^ _globalKey;

    public uint Length => (uint) _encryptedData.Count;

    public byte[] Data => _encryptedData.ToArray();

    public void Encrypt(string input)
    {
        if (_index <= 0)
            throw new ArgumentOutOfRangeException(nameof(_index));

        // Encrypt string
        byte[] data = RXOR(Encoding.UTF8.GetBytes(input), out int key);

        // Add the metadata required to decrypt the string, length and XOR key
        byte[] temp = new byte[8];
        BitConverter.GetBytes(data.Length).CopyTo(temp, 0);
        BitConverter.GetBytes(key).CopyTo(temp, 4);

        // Set index to the index of the last element
        _index = _encryptedData.Count;

        // Add the metadata and the encrypted string data
        _encryptedData.AddRange(temp);
        _encryptedData.AddRange(data);
    }

    private byte[] RXOR(byte[] data, out int key)
    {
        key = RandomNumberGenerator.GetInt32(int.MaxValue);

        // RXOR Cipher: reverse array order and decrypt byte by byte using single XOR
        int n = data.Length - 1;
        for (int i = 0; i < n; i++, n--)
        {
            data[i] ^= data[n];
            data[n] ^= (byte) (data[i] ^ key);
            data[i] ^= data[n];
        }

        if (data.Length % 2 != 0)
            data[data.Length >> 1] ^= (byte) key; // x >> 1 == x / 2

        return data;
    }
}
