# CryptStr.Fody

Original Project URL:
[https://archive.codeplex.com/?p=cryptstr](https://archive.codeplex.com/?p=cryptstr)

This repository contains CryptStr.Fody updated for Fody 3 with .NET Standard 2 and >= .NET 4.6 support.

# About
A post-build weaver that encrypts literal strings in your .NET assemblies without breaking ClickOnce.

CryptStr.Fody modifies a .NET assembly (not source code) by encrypting literal strings (e.g. passwords and connection strings) to hide them from reflection/decompilers. It does not encrypt strings declared as constant class members, but that can be fixed by changing them from "constant" to "static readonly".

CryptStr.Fody is a Fody plugin. Fody is an extensible tool for "weaving" .NET assemblies. For more information about Fody, see [https://github.com/Fody/Fody](https://github.com/Fody/Fody).

CryptStr works by integrating into your assembly's build process in Visual Studio. To use it, make sure you have the NuGet extension installed for Visual Studio (it comes with VS 2012). Then search for the CryptStr.Fody package and install it. That's it! The NuGet page for CryptStr is at [http://www.nuget.org/packages/CryptStr.Fody3/](http://www.nuget.org/packages/CryptStr.Fody3/)

You can use a reflection tool such as dnSpy to verify that your literal strings are no longer visible.

By default, CryptStr encrypts strings of length 1 - 1000000. If you feel this causes an issue with the size or performance of your assembly, you can reduce the number of strings that get encrypted by changing the minimum and/or maximum length of the strings to be encrypted. After all, you probably don't have any 1 or 1000 character passwords. You can set the minimum and maximum length of strings to encrypt in the FodyWeavers.xml file like this.

```xml
<?xml version="1.0" encoding="utf-8"?>
<Weavers>
  <CryptStr MinLen="2" MaxLen="10"/>
</Weavers>
```