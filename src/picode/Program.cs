using SixLabors.ImageSharp;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace picode
{
    class Program
    {
        static int _blockSize = 128;

        static void InitKeyIV(RijndaelManaged c, string pass)
        {
            const int Iterations = 234;
            byte[] salt = new byte[] { 1, 2, 23, 234, 37, 48, 134, 63, 248, 4 };
            using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(pass, salt, Iterations))
            {
                c.Key = rfc2898DeriveBytes.GetBytes(c.BlockSize / 8);
                Console.WriteLine(string.Format("Key: {0}", Convert.ToBase64String(c.Key)));
                c.IV = rfc2898DeriveBytes.GetBytes(c.BlockSize / 8);
                Console.WriteLine(string.Format("IV: {0}", Convert.ToBase64String(c.IV)));
            }
        }

        static void ShowUsage()
        {
            Console.WriteLine("To encrypt: picode -e [FileName] [password]");
            Console.WriteLine("To decrypt: picode -d [EncryptedFile] [OutputFile] [password]");
        }

        static void Main(string[] args)
        {
            if (args == null || (!(args.Length == 3 && args[0] == "-e") && !(args[0] == "-d" && args.Length == 4)))
            {
                ShowUsage();
                return;
            }

            try
            {

                if (args[0] == "-d")
                {
                    DecryptAndSave(args[1], args[2], args[3]);
                }
                else
                {
                    using (var buffer = ReadAndEncryptFile(args[1], args[2]))
                    {
                        CreateImageFromBuffer(args[1] + ".bmp", buffer);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in encrypting/decrypting file:");
                Console.Write(ex.ToString());
            }
        }

        static MemoryStream ReadAndEncryptFile(string path, string pass)
        {
            var buf = File.ReadAllBytes(path);
            var outStream = new MemoryStream(buf.Length);
            try
            {
                using (RijndaelManaged RMCrypto = new RijndaelManaged())
                {
                    RMCrypto.BlockSize = _blockSize;
                    InitKeyIV(RMCrypto, pass);
                    // -- dunno if i should dispose this since it also disposes my byte stream
                    CryptoStream cs = new CryptoStream(outStream,
                        RMCrypto.CreateEncryptor(),
                        CryptoStreamMode.Write);

                    cs.Write(buf, 0, buf.Length);
                    cs.FlushFinalBlock();

                    // -- return encrypted bytestream
                    return outStream;
                }
            }
            catch
            {
                if (outStream != null)
                {
                    outStream.Dispose();
                    outStream = null;
                }
                throw;
            }
        }

        static void CreateImageFromBuffer(string savePath, MemoryStream stream)
        {
            int width = 3 * 1024;
            var buf = BitConverter.GetBytes(stream.Length).Concat(stream.GetBuffer().Take((int)stream.Length).ToArray()).ToArray();
            var height = (int)buf.LongLength / width;
            if (buf.LongLength % width != 0)
                height += 1;
            
            using (var img = new Image<Rgba32>(Configuration.Default, width / 3, height))
            {
                for (long i = 0; i < height; i++)
                {
                    for (long w = 0; w < (width / 3); w++)
                    {
                        var index = (i * width) + (w * 3);
                        var bytes = buf.Skip((int)index).Take(3).ToArray();
                        if (bytes.Length < 4)
                            bytes = bytes.Concat(Enumerable.Repeat<byte>(0, 4 - bytes.Length)).ToArray();

                        img[(int)w, (int)i] = new Rgba32(BitConverter.ToUInt32(bytes, 0));
                    }
                }
                using (var s = File.Create(savePath))
                {
                    img.SaveAsBmp(s);
                }
            }
        }
        static void DecryptAndSave(string filePath, string outPath, string pass)
        {
            using (var mem = new MemoryStream())
            {

                using (var bitmap = Image.Load<Rgba32>(filePath))
                {
                    for (long i = 0; i < bitmap.Height; i++)
                    {
                        for (long w = 0; w < bitmap.Width; w++)
                        {
                            var pix = bitmap[(int)w, (int)i];
                            mem.WriteByte(pix.R);
                            mem.WriteByte(pix.G);
                            mem.WriteByte(pix.B);
                        }
                    }
                }

                // -- determine stream size
                var buf = mem.GetBuffer();
                var length = BitConverter.ToInt64(buf, 0);

                using (var fs = new FileStream(outPath, FileMode.Create))
                using (RijndaelManaged RMCrypto = new RijndaelManaged())
                {
                    RMCrypto.BlockSize = _blockSize;
                    InitKeyIV(RMCrypto, pass);
                    CryptoStream cs = new CryptoStream(fs,
                        RMCrypto.CreateDecryptor(),
                        CryptoStreamMode.Write);
                    cs.Write(buf, 8, (int)length);
                    cs.FlushFinalBlock();
                }
            }
        }
    }
}
