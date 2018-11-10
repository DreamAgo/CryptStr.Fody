using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Xml.Linq;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;

namespace CryptStr
{
    /// <summary>
    /// This class is required by Fody.  Fody will initialize various public properties
    /// and call Execute().
    /// </summary>
    public class ModuleWeaver
    {
        // Init logging delegates to make testing easier
        public ModuleWeaver()
        {
            LogInfo = m => { };
        }

        // Will log an informational message to MSBuild.  Set by Fody.
        public Action<string> LogInfo { get; set; }

        // An instance of Mono.Cecil.ModuleDefinition for processing.
        // Required by Fody.
        public ModuleDefinition ModuleDefinition { get; set; }

        // XML element from FodyWeavers.xml
        public XElement Config { get; set; }

        private int _minLen = 1;
        private int _maxLen = 1000000;

        // Unencryted strings converted to UTF8 bytes, concatenated together.
        private List<byte> _stringBytes = new List<byte>(10000);
        private int _byteCount;

        // Key used to encrypt/decrypt the bytes.
        private static byte[] _key;

        // Result of encrypting _stringBytes and converting to base64.
        private static string _cipherBytes; 

        private static byte[] _decryptedBytes;
        private FieldDefinition _decryptedField;

        private MethodDefinition _decryptMethod;
        private MethodDefinition _lookupMethod;

        // Encrypts all (or most) strings in the assembly.
        // Injects a decryption method into the assembly.
        public void Execute()
        {
            //TypeDefinition moduleClass = ModuleDefinition
            //    .GetAllTypes()
            //    .Single(typedef => typedef.Name == "<Module>");

            //FieldDefinition myBytes = new FieldDefinition("myBytes"
            //    , FieldAttributes.Private | FieldAttributes.Static //| FieldAttributes.HasFieldRVA
            //    , ModuleDefinition.Import(typeof(byte[])));

            //myBytes.InitialValue = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };

            // moduleClass.Fields.Add(myBytes);

            //return;

            if (Config.HasAttributes)
            {
                var minattr = Config.Attribute("MinLen");
                var maxattr = Config.Attribute("MaxLen");

                if (minattr != null) int.TryParse(minattr.Value, out _minLen);
                if (maxattr != null) int.TryParse(maxattr.Value, out _maxLen);
            }

            CreateMethods();
            
            //Loop through the modules
            LogInfo("Processing modules");
            foreach (ModuleDefinition moduleDefinition in ModuleDefinition.Assembly.Modules)
            {
                LogInfo("Module " + moduleDefinition.Name ?? "<null>");

                //Go through each type
                foreach (TypeDefinition typeDefinition in moduleDefinition.GetAllTypes())
                {
                    //Go through each method
                    foreach (MethodDefinition methodDefinition in typeDefinition.Methods)
                    {
                        if (methodDefinition.HasBody)
                        {
                            ProcessMethod(methodDefinition.Body);
                        }
                    }
                }
            }

            byte[] plainText = _stringBytes.ToArray();
            _stringBytes = null;
            _cipherBytes  = EncryptBytes(plainText);
            _byteCount = plainText.Length;
            plainText = null;
            FinishDecryptor();
        }

        private string EncryptBytes(byte[] plainText)
        {
            string pw = Guid.NewGuid().ToString();
            byte[] salt = Guid.NewGuid().ToByteArray();
            var keyGenerator = new Rfc2898DeriveBytes(pw, salt);
            _key = keyGenerator.GetBytes(16);

            using (AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider() { Padding=PaddingMode.None })
            using (ICryptoTransform cryptoTransform = aesProvider.CreateEncryptor(_key, _key))
            using (MemoryStream memStream = new MemoryStream())
            using (CryptoStream cryptoStream = new CryptoStream(memStream, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(plainText.ToArray(), 0, plainText.Length);

                // If padding is required, we add our own.
                if (plainText.Length % 16 != 0)
                {
                    byte[] pad = new byte[16 - plainText.Length % 16];
                    cryptoStream.Write(pad, 0, pad.Length);
                }

                // This must be called to write all the bytes to memStream, but
                // can only be called once.
                cryptoStream.FlushFinalBlock();

                byte[] bytes = memStream.GetBuffer();
                int len = (int)memStream.Length;
                int pos = (int)memStream.Position;
                return Convert.ToBase64String(bytes, 0, len, Base64FormattingOptions.None);
            }
        }

        private void CreateMethods()
        {
            foreach (TypeDefinition td in ModuleDefinition.GetAllTypes())
                if (td.Name == "<Module>")
                {
                    // Add a private static field called CryptBytes to contain the decrypted byte[].  
                    _decryptedField = new FieldDefinition("CryptBytes"
                        , FieldAttributes.Private | FieldAttributes.Static
                        , ModuleDefinition.Import(typeof(byte[])));
                    td.Fields.Add(_decryptedField);

                    // Create an empty method called CryptInit (to be completed later) to initialize CryptBytes.
                    // This is called by CryptGet, so it has to be created first.
                    _decryptMethod = new MethodDefinition("CryptInit", MethodAttributes.HideBySig | MethodAttributes.Static | MethodAttributes.CompilerControlled, ModuleDefinition.Import(typeof(void)));
                    _decryptMethod.Body = new MethodBody(_decryptMethod);
                    td.Methods.Add(_decryptMethod);

                    // Create a method called LookupStr to that can be called to extract decrypted strings from decryptedBytes.
                    CreateLookup(td);
                    break;
                }
        }

        private void CreateLookup(TypeDefinition moduleType)
        {            
            var getUtf8 = ModuleDefinition.Import(typeof(Encoding).GetMethod("get_UTF8", Type.EmptyTypes));
            var getString = ModuleDefinition.Import(typeof(Encoding).GetMethod("GetString", new[] { typeof(byte[]), typeof(Int32), typeof(Int32) }));

            _lookupMethod = new MethodDefinition("CryptGet", MethodAttributes.HideBySig | MethodAttributes.Static, ModuleDefinition.Import(typeof(string)));
            _lookupMethod.Parameters.Add(new ParameterDefinition("ndx", ParameterAttributes.None, ModuleDefinition.Import(typeof(int))));
            _lookupMethod.Parameters.Add(new ParameterDefinition("len", ParameterAttributes.None, ModuleDefinition.Import(typeof(int))));
            _lookupMethod.Body = new MethodBody(_lookupMethod);
            var il = _lookupMethod.Body.GetILProcessor();

            // Add instructions that mimic LookupTemplate().

            var beforeIf = il.Create(OpCodes.Ldsfld, _decryptedField);
            il.Append(beforeIf);
            il.Append(il.Create(OpCodes.Call, _decryptMethod));
            var afterIf = il.Create(OpCodes.Call, getUtf8);
            il.Append(afterIf);
            il.InsertAfter(beforeIf, il.Create(OpCodes.Brtrue_S, afterIf));
            il.Append(il.Create(OpCodes.Ldsfld, _decryptedField));
            il.Append(il.Create(OpCodes.Ldarg_0));
            il.Append(il.Create(OpCodes.Ldarg_1));
            il.Append(il.Create(OpCodes.Callvirt, getString));
            il.Append(il.Create(OpCodes.Ret));

            moduleType.Methods.Add(_lookupMethod);
        }

        // The code in CreateLookup() came from looking at the IL 
        // that the compiler generated for this method.
        private static string LookupTemplate(int ndx, int len)
        {
            if (_decryptedBytes == null) DecryptorTemplate();
            return Encoding.UTF8.GetString(_decryptedBytes, ndx, len);
        }

        private void FinishDecryptor()
        {
            var moduleType = _decryptMethod.DeclaringType;

            var il = _decryptMethod.Body.GetILProcessor();

            _decryptMethod.Body.InitLocals = true;
            VariableDefinition keyBytes = _decryptMethod.AddLocal(typeof(byte[]));
            VariableDefinition aesProvider = _decryptMethod.AddLocal(typeof(AesCryptoServiceProvider));
            VariableDefinition cryptoTransform = _decryptMethod.AddLocal(typeof(ICryptoTransform));
            VariableDefinition memStream = _decryptMethod.AddLocal(typeof(MemoryStream));
            VariableDefinition cryptoStream = _decryptMethod.AddLocal(typeof(CryptoStream));
            
            // Get references to the methods we'll be calling.
            var aesCtor = ModuleDefinition.ImportReference(typeof(AesCryptoServiceProvider).GetConstructor(Type.EmptyTypes));
            var setPadding = ModuleDefinition.ImportReference(typeof(SymmetricAlgorithm).GetMethod("set_Padding", new[] { typeof(PaddingMode) }));
            var fromBase64 = ModuleDefinition.ImportReference(typeof(Convert).GetMethod("FromBase64String", new[] { typeof(string) }));
            var createDecryptor = ModuleDefinition.ImportReference(typeof(SymmetricAlgorithm).GetMethod("CreateDecryptor", new[] { typeof(byte[]), typeof(byte[]) }));
            var memStreamCtor = ModuleDefinition.ImportReference(typeof(MemoryStream).GetConstructor(new[] { typeof(byte[]) }));
            var cryptoStreamCtor = ModuleDefinition.ImportReference(typeof(CryptoStream).GetConstructor(new[] { typeof(Stream), typeof(ICryptoTransform), typeof(CryptoStreamMode) }));
            var readStream = ModuleDefinition.ImportReference(typeof(Stream).GetMethod("Read", new[] { typeof(byte[]), typeof(int), typeof(int) }));
            var disposeStream = ModuleDefinition.ImportReference(typeof(Stream).GetMethod("Dispose", Type.EmptyTypes));
            var dispose = ModuleDefinition.ImportReference(typeof(IDisposable).GetMethod("Dispose", Type.EmptyTypes));
            var disposeSymmetric = ModuleDefinition.ImportReference(typeof(SymmetricAlgorithm).GetMethod("Dispose", Type.EmptyTypes));

            il.Append(il.Create(OpCodes.Ldstr, Convert.ToBase64String(_key)));
            il.Append(il.Create(OpCodes.Call, fromBase64));
            il.Append(il.Create(OpCodes.Stloc_0));
            il.Append(il.Create(OpCodes.Newobj, aesCtor));
            il.Append(il.Create(OpCodes.Stloc_1));
            il.Append(il.Create(OpCodes.Ldloc_1));
            il.Append(il.Create(OpCodes.Ldc_I4_1));
            il.Append(il.Create(OpCodes.Callvirt, setPadding));
            il.Append(il.Create(OpCodes.Ldloc_1));
            il.Append(il.Create(OpCodes.Ldloc_0));
            il.Append(il.Create(OpCodes.Ldloc_0));
            il.Append(il.Create(OpCodes.Callvirt, createDecryptor));
            il.Append(il.Create(OpCodes.Stloc_2));
            il.Append(il.Create(OpCodes.Ldstr, _cipherBytes));
            il.Append(il.Create(OpCodes.Call, fromBase64));
            il.Append(il.Create(OpCodes.Newobj, memStreamCtor));
            il.Append(il.Create(OpCodes.Stloc_3));
            il.Append(il.Create(OpCodes.Ldloc_3));
            il.Append(il.Create(OpCodes.Ldloc_2));
            il.Append(il.Create(OpCodes.Ldc_I4_0));
            il.Append(il.Create(OpCodes.Newobj, cryptoStreamCtor));
            il.Append(il.Create(OpCodes.Stloc_S, cryptoStream));
            il.Append(il.Create(OpCodes.Ldc_I4, _byteCount));
            il.Append(il.Create(OpCodes.Newarr, ModuleDefinition.Import(typeof(byte))));
            il.Append(il.Create(OpCodes.Stsfld, _decryptedField));
            il.Append(il.Create(OpCodes.Ldloc_S, cryptoStream));
            il.Append(il.Create(OpCodes.Ldsfld, _decryptedField));
            il.Append(il.Create(OpCodes.Ldc_I4_0));
            il.Append(il.Create(OpCodes.Ldc_I4, _byteCount));
            il.Append(il.Create(OpCodes.Callvirt, readStream));
            il.Append(il.Create(OpCodes.Pop));
            il.Append(il.Create(OpCodes.Ldloc_S, cryptoStream));
            il.Append(il.Create(OpCodes.Callvirt, disposeStream));
            il.Append(il.Create(OpCodes.Ldloc_3));
            il.Append(il.Create(OpCodes.Callvirt, disposeStream));
            il.Append(il.Create(OpCodes.Ldloc_2));
            il.Append(il.Create(OpCodes.Callvirt, dispose));
            il.Append(il.Create(OpCodes.Ldloc_1));
            il.Append(il.Create(OpCodes.Callvirt, disposeSymmetric));
            
            il.Append(il.Create(OpCodes.Ret));            
        }

        // The code in FinishDecryptor() came from looking at the IL 
        // that the compiler generated for this method.
        private static void DecryptorTemplate()
        {
            byte[] keyBytes = Convert.FromBase64String("key in base64");
            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            aesProvider.Padding = PaddingMode.None;
            ICryptoTransform cryptoTransform = aesProvider.CreateDecryptor(keyBytes, keyBytes);
            MemoryStream memStream = new MemoryStream(Convert.FromBase64String("A 'hardcoded' base64 string representing the encrypted bytes."));
            CryptoStream cryptoStream = new CryptoStream(memStream, cryptoTransform, CryptoStreamMode.Read);

            _decryptedBytes = new byte[999999]; // Use actual length of the base64 string.
            cryptoStream.Read(_decryptedBytes, 0, 999999);

            cryptoStream.Dispose();
            memStream.Dispose();
            cryptoTransform.Dispose();
            aesProvider.Dispose();
        }

        private void ProcessMethod(MethodBody body)
        {
            body.SimplifyMacros();

            var il = body.GetILProcessor();
            var instructionsToExpand = FindStrings(body);

            //Fix each ldstr instruction found
            foreach (Instruction instruction in instructionsToExpand)
            {
                // First get the original string and convert it to a UTF8 byte array.
                string originalValue = instruction.Operand.ToString();
                byte[] bytes = Encoding.UTF8.GetBytes(originalValue);

                // Change the instruction's properties to load the index of the string's bytes in _stringBytes.
                // Do not replace the instruction itself or bad problems occur if the instruction is the target of a branch/jump.
                instruction.OpCode = OpCodes.Ldc_I4;
                instruction.Operand = _stringBytes.Count;

                _stringBytes.AddRange(bytes);

                // Now load the number of bytes
                Instruction loadByteLen = il.Create(OpCodes.Ldc_I4, bytes.Length);
                il.InsertAfter(instruction, loadByteLen);

                //Process the decryption
                Instruction call = il.Create(OpCodes.Call, _lookupMethod);
                il.InsertAfter(loadByteLen, call);
            }

            body.OptimizeMacros();
            return;

        }

        // Scans the MethodBody and returns a list of the "ldstr" instructions found within.
        private List<Instruction> FindStrings(MethodBody body)
        {
            var LoadStrs = new List<Instruction>();

            foreach (Instruction instruction in body.Instructions)
            {
                //Find the call statement
                switch (instruction.OpCode.Name)
                {
                    case "ldstr":
                        if (instruction.Operand is string && (instruction.Operand as string).Length >= _minLen && (instruction.Operand as string).Length <= _maxLen)
                        {
                            LoadStrs.Add(instruction);
                        }
                        break;
                }
            }

            return LoadStrs;
        }
    }
}