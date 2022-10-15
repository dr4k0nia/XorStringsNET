// See https://aka.ms/new-console-template for more information

using AsmResolver.DotNet;
using SimpleStringEncryption;


if (!File.Exists(args[0]))
{
    Console.WriteLine($"File not found: {args[0]}");
    Console.ReadKey();
    return;
}

var module = ModuleDefinition.FromFile(args[0]);
var stringEncryption = new StringEncryption(module);

stringEncryption.Run();

string outputPath = args[0].Insert(args[0].Length - 4, "_packed");
module.Write(outputPath);

Console.WriteLine($"Strings have been encrypted: \nOutput: {outputPath}");
Console.ReadKey();
