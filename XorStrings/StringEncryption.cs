using System.Security.Cryptography;
using System.Text;
using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Cloning;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables.Rows;

namespace SimpleStringEncryption;

public class StringEncryption
{
    private readonly EncryptionService _encryptionService;
    private readonly ModuleDefinition _module;

    private FieldDefinition _arrayPtrField = null!;

    private MethodDefinition _decryptionMethod = null!;

    private MethodDefinition _placeholderMethod = null!;

    public StringEncryption(ModuleDefinition module)
    {
        _module = module;
        _encryptionService = new EncryptionService();
    }

    public void Run()
    {
        // Inject the runtime which contains our decryption method
        InjectRuntime();

        // Process CIL method bodies to find and encrypt all strings
        ProcessModule();

        // Prepare the struct with the encrypted data
        SetupStruct();

        // Patch the placeholder values in the runtime
        PatchRuntimePlaceholders();
    }

    private void InjectRuntime()
    {
        // Load the runtime module
        string baseDirectory = AppContext.BaseDirectory;
        var implantModule = ModuleDefinition.FromFile(Path.Combine(baseDirectory, "Runtime.dll"));

        // Initialize a new instance of the member cloner for the target module
        var cloner = new MemberCloner(_module);

        // Get the Runtime class from the implant module and clone it
        var loader = implantModule.GetAllTypes().First(t => t.Name == "Runtime");
        cloner.Include(loader, true);
        var result = cloner.Clone();

        // Add the cloned type into the target module
        foreach (var clonedType in result.ClonedTopLevelTypes)
            _module.TopLevelTypes.Add(clonedType);

        result.GetClonedMember(loader).Namespace = Utf8String.Empty;

        _decryptionMethod = (MethodDefinition) result.ClonedMembers.First(m => m.Name == "Decrypt");

        // Assign random GUID based names to the declaring class and the decryption method
        _decryptionMethod.Name = GetGuidString();
        _decryptionMethod.DeclaringType!.Name = GetGuidString();

        // Resolve the placeholder method for cpblk
        _placeholderMethod = (MethodDefinition) result.ClonedMembers.First(m => m.Name == "cpblk");
    }

    private void ProcessModule()
    {
        // Go trough all types that have at least one method
        foreach (var type in _module.GetAllTypes().Where(t => t.Methods.Count > 0))
        {
            // Skip this type since its the injected runtime class
            if (type == _decryptionMethod.DeclaringType)
                continue;

            // Go trough all methods of the type
            foreach (var method in type.Methods)
            {
                // Skip non CIL methods
                if (method.CilMethodBody == null)
                    continue;

                // Iterate over the method bodies CIL instructions
                var instructions = method.CilMethodBody.Instructions;
                for (int i = 0; i < instructions.Count; i++)
                {
                    // Find strings
                    if (instructions[i].OpCode != CilOpCodes.Ldstr)
                        continue;

                    if (instructions[i].Operand == null)
                        continue;

                    // Since empty strings cannot be encrypted, give them a negative id so the runtime
                    // can handle them separately
                    if ((string) instructions[i].Operand! == string.Empty)
                    {
                        // Negate index for empty strings, the runtime will handle negative index values in a special way
                        instructions[i].ReplaceWith(CilOpCodes.Ldc_I4, -(_encryptionService.Index));

                        instructions.Insert(i + 1, CilOpCodes.Call, _decryptionMethod);
                        continue;
                    }

                    _encryptionService.Encrypt((string) instructions[i].Operand!);

                    // Replace the string assignment with the encrypted id (index)
                    instructions[i].ReplaceWith(CilOpCodes.Ldc_I4, _encryptionService.Index);

                    instructions.Insert(i + 1, CilOpCodes.Call, _decryptionMethod);
                }

                instructions.OptimizeMacros();
            }
        }
    }

    private void SetupStruct()
    {
        var staticStruct = _decryptionMethod.DeclaringType?.NestedTypes[0];

        // Apply the necessary attributes
        staticStruct!.Attributes = TypeAttributes.ExplicitLayout | TypeAttributes.BeforeFieldInit
                                                                 | TypeAttributes.NestedPrivate;

        staticStruct.Name = GetGuidString();

        // Add new field based on the struct
        var field = new FieldDefinition(GetGuidString(),
            FieldAttributes.Private | FieldAttributes.Static | FieldAttributes.HasFieldRva,
            staticStruct.ToTypeSignature());

        _decryptionMethod.DeclaringType?.Fields.Add(field);

        _arrayPtrField = field;

        // Add data to FieldRva and add ClassLayout with size being the length of the encrypted data
        staticStruct.ClassLayout = new ClassLayout(1, _encryptionService.Length);
        field.FieldRva = new DataSegment(_encryptionService.Data);
    }

    private void PatchRuntimePlaceholders()
    {
        var instructions = _decryptionMethod.CilMethodBody?.Instructions;

        if (instructions == null)
            throw new ArgumentNullException();

        // Patch the placeholder for the data address with the field containing the fieldrva
        var patch = instructions?.First(i => i.IsLdcI4() && i.GetLdcI4Constant() == 0x420);

        patch?.ReplaceWith(CilOpCodes.Ldsflda, _arrayPtrField);

        // Replace the call to the cpblk placeholder method with the actual cpblk CIL instruction
        patch = instructions?.First(i => i.Operand == _placeholderMethod);

        patch?.ReplaceWith(CilOpCodes.Cpblk);

        _decryptionMethod.DeclaringType!.Methods.Remove(_placeholderMethod);
    }

    private static string GetGuidString()
    {
        return Guid.NewGuid().ToString().ToUpper();
    }
}
