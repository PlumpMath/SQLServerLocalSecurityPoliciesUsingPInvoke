
using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;


namespace LsaSecurity
 {
     /*
	 
	   1) LsaWrapper class credit: Willy Denoyette [MVP]
       http://www.hightechtalks.com/csharp/lsa-functions-276626.html

		a) Added support for:
           LsaLookupSids
	 
	 
	   2)  Roel van Lisdonk
    	   How to grant “Log on as a service” rights to an user account, using PowerShell
		   https://www.roelvanlisdonk.nl/2010/03/24/how-to-grant-log-on-as-a-service-rights-to-an-user-account-using-powershell/
	 
	   3) Jordan Mills
		  https://jordanmills.wordpress.com/2014/07/31/change-local-user-rights-assignment-from-powershell/
		  
		  a) Added LsaWrapperCaller classes
		
	*/		

			
     using System.Runtime.InteropServices;
     using System.Security;
     using System.Management;
     using System.Runtime.CompilerServices;
     using System.ComponentModel;

     using LSA_HANDLE = IntPtr;

     public class Program
     {
		 public static void Main()
		 {
			 using (LsaWrapper lsaSec = new LsaWrapper())
			 {
				 
				string rights = null;
				
				rights = "SeManageVolumePrivilege";
				
				Console.WriteLine("Calling GetUsersWithPrivilege for rights " + rights);
				
				string[] accounts = lsaSec.GetUsersWithPrivilege(rights);
				
				if (accounts == null)
				{
					return;
					
				}
				
				int iNumberofAccounts = accounts.Length;
				int i;
				
				for (i=0; i<iNumberofAccounts; i++)
				{
					Console.WriteLine(accounts[i]);
				}
				

			 }

		 }
     }



    [StructLayout(LayoutKind.Sequential)]
     struct LSA_OBJECT_ATTRIBUTES
     {
     internal int Length;
     internal IntPtr RootDirectory;
     internal IntPtr ObjectName;
     internal int Attributes;
     internal IntPtr SecurityDescriptor;
     internal IntPtr SecurityQualityOfService;
     }
     [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
     struct LSA_UNICODE_STRING
     {
     internal ushort Length;
     internal ushort MaximumLength;
     [MarshalAs(UnmanagedType.LPWStr)]
     internal string Buffer;
     }

     sealed class Win32Sec
     {
     [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
     SuppressUnmanagedCodeSecurityAttribute]
     internal static extern uint LsaOpenPolicy(
     LSA_UNICODE_STRING[] SystemName,
     ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
     int AccessMask,
     out IntPtr PolicyHandle
     );

     [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
     SuppressUnmanagedCodeSecurityAttribute]
     internal static extern uint LsaAddAccountRights(
     LSA_HANDLE PolicyHandle,
     IntPtr pSID,
     LSA_UNICODE_STRING[] UserRights,
     int CountOfRights
     );

     [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
         SuppressUnmanagedCodeSecurityAttribute]
     internal static extern uint LsaRemoveAccountRights(
     LSA_HANDLE PolicyHandle,
     IntPtr pSID,
     bool allRights,
     LSA_UNICODE_STRING[] UserRights,
     int CountOfRights
     );

     [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
         SuppressUnmanagedCodeSecurityAttribute]
     internal static extern uint LsaEnumerateAccountsWithUserRight(
         LSA_HANDLE PolicyHandle,
         LSA_UNICODE_STRING[] UserRights,
         out IntPtr EnumerationBuffer,
         out int CountReturned
     );

     [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
     SuppressUnmanagedCodeSecurityAttribute]
     internal static extern uint LsaLookupSids(
         LSA_HANDLE PolicyHandle,
         int count,
         IntPtr buffer,
         out LSA_HANDLE domainList,
         out LSA_HANDLE nameList
     );



    [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
     SuppressUnmanagedCodeSecurityAttribute]
     internal static extern int LsaLookupNames2(
     LSA_HANDLE PolicyHandle,
     uint Flags,
     uint Count,
     LSA_UNICODE_STRING[] Names,
     ref IntPtr ReferencedDomains,
     ref IntPtr Sids
     );



    [DllImport("advapi32")]
     internal static extern int LsaNtStatusToWinError(int NTSTATUS);

     [DllImport("advapi32")]
     internal static extern int LsaClose(IntPtr PolicyHandle);

     [DllImport("advapi32")]
     internal static extern int LsaFreeMemory(IntPtr Buffer);

     }

     public sealed class LsaWrapper : IDisposable
     {
	 
		 private bool _writeToConsole = false;

		 [StructLayout(LayoutKind.Sequential)]
		 struct LSA_TRUST_INFORMATION
		 {
			 internal LSA_UNICODE_STRING Name;
			 internal IntPtr Sid;
		 }
		 [StructLayout(LayoutKind.Sequential)]
		 struct LSA_TRANSLATED_SID2
		 {
			 internal SidNameUse Use;
			 internal IntPtr Sid;
			 internal int DomainIndex;
			 uint Flags;
		 }

		 //[StructLayout(LayoutKind.Sequential)]
		 //struct LSA_REFERENCED_DOMAIN_LIST
		 //{
		 //    internal uint Entries;
		 //    internal LSA_TRUST_INFORMATION Domains;
		 //}
		 // Commented by KaushalendraATgmail.com

		 [StructLayout(LayoutKind.Sequential)]
		 internal struct LSA_REFERENCED_DOMAIN_LIST
		 {
			 internal uint Entries;
			 internal IntPtr Domains;
		 }

		 [StructLayout(LayoutKind.Sequential)]
		 struct LSA_ENUMERATION_INFORMATION
		 {
			 internal LSA_HANDLE PSid;
		 }

		 [StructLayout(LayoutKind.Sequential)]
		 struct LSA_SID
		 {
			 internal uint Sid;
		 }

		 [StructLayout(LayoutKind.Sequential)]
		 struct LSA_TRANSLATED_NAME
		 {
			 internal SidNameUse Use;
			 internal LSA_UNICODE_STRING Name;
			 internal int DomainIndex;
		 }

		 enum SidNameUse : int
		 {
			 User = 1,
			 Group = 2,
			 Domain = 3,
			 Alias = 4,
			 KnownGroup = 5,
			 DeletedAccount = 6,
			 Invalid = 7,
			 Unknown = 8,
			 Computer = 9
		 }

		 enum Access : int
		 {
			 POLICY_READ = 0x20006,
			 POLICY_ALL_ACCESS = 0x00F0FFF,
			 POLICY_EXECUTE = 0X20801,
			 POLICY_WRITE = 0X207F8
		 }
		 const uint STATUS_ACCESS_DENIED = 0xc0000022;
		 const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
		 const uint STATUS_NO_MEMORY = 0xc0000017;

		 IntPtr lsaHandle;

		 public LsaWrapper()
			 : this(null)
		 { }
		 
		 // // local system if systemName is null
		 public LsaWrapper(string systemName)
		 {
			 LSA_OBJECT_ATTRIBUTES lsaAttr;
			 lsaAttr.RootDirectory = IntPtr.Zero;
			 lsaAttr.ObjectName = IntPtr.Zero;
			 lsaAttr.Attributes = 0;
			 lsaAttr.SecurityDescriptor = IntPtr.Zero;
			 lsaAttr.SecurityQualityOfService = IntPtr.Zero;
			 lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
			 lsaHandle = IntPtr.Zero;
			 LSA_UNICODE_STRING[] system = null;
			 if (systemName != null)
			 {
				 system = new LSA_UNICODE_STRING[1];
				 system[0] = InitLsaString(systemName);
			 }

			 uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr, (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
			 
			 if (ret == 0)
			 {
				return;
			 }
			 
			 if (ret == STATUS_ACCESS_DENIED)
			 {
				throw new UnauthorizedAccessException();
			 }
			 
			 if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY))
			 {
				throw new OutOfMemoryException();
			 }
			 
			 throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
		 }
		 
		 /*
			2016-11-03 DAdeniji - Added Dispose
		 */
		public void Dispose()
		{
			
			if (lsaHandle != IntPtr.Zero)
			{
				
				Win32Sec.LsaClose(lsaHandle);
				lsaHandle = IntPtr.Zero;
			}
			
			GC.SuppressFinalize(this);
		}
		
		~LsaWrapper()
		{
			Dispose();
		}
		// helper functions

		IntPtr GetSIDInformation(string account)
		{
			LSA_UNICODE_STRING[] names = new LSA_UNICODE_STRING[1];
			LSA_TRANSLATED_SID2 lts;
			IntPtr tsids = IntPtr.Zero;
			IntPtr tdom = IntPtr.Zero;
			names[0] = InitLsaString(account);
			lts.Sid = IntPtr.Zero;
			int ret = Win32Sec.LsaLookupNames2(lsaHandle, 0, 1, names, ref tdom, ref tsids);
			if (ret != 0)
			throw new Win32Exception(Win32Sec.LsaNtStatusToWinError(ret));
			lts = (LSA_TRANSLATED_SID2)Marshal.PtrToStructure(tsids,
			typeof(LSA_TRANSLATED_SID2));
			Win32Sec.LsaFreeMemory(tsids);
			Win32Sec.LsaFreeMemory(tdom);
			return lts.Sid;
		}
		 
		static LSA_UNICODE_STRING InitLsaString(string s)
		{
			
			// Unicode strings max. 32KB
			if (s.Length > 0x7ffe)
			{	
				throw new ArgumentException("String too long");
			}
			
			LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
			lus.Buffer = s;
			lus.Length = (ushort)(s.Length * sizeof(char));
			lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
			
			return lus;
			
		}

		public string[] GetUsersWithPrivilege(string privilege)
		{
			//LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
			LSA_UNICODE_STRING[] privileges = null;
			
			//privileges[0] = InitLsaString(privilege);

			IntPtr buffer = IntPtr.Zero;
			int count;
			//long count;
			uint ret = 0;
			
			string[] domainUserName = null;
			
			List<string> objListofSteps = new List<string>();
			
			LSA_HANDLE domains;
			LSA_HANDLE names;
			
			//string[] retNames = new string[count];
			string[] retNames = null;
			
			//List<int> currentDomain = new List<int>();
			List<int> currentDomain;
			
			int domainCount = 0;

			//LSA_TRANSLATED_NAME[] lsaNames = new LSA_TRANSLATED_NAME[count];
			LSA_TRANSLATED_NAME[] lsaNames;
				
			try
			{
				
				//LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
				privileges = new LSA_UNICODE_STRING[1];
				
				objListofSteps.Add("Invoking InitLsaString(privilege)");
				
				privileges[0] = InitLsaString(privilege);
				
				objListofSteps.Add("Win32Sec.LsaEnumerateAccountsWithUserRight Initiating ....");
			
				ret = Win32Sec.LsaEnumerateAccountsWithUserRight
						(
							  lsaHandle
							, privileges
							, out buffer
							, out count
						);

				objListofSteps.Add("Win32Sec.LsaEnumerateAccountsWithUserRight - Completed");

				objListofSteps.Add("Win32Sec.LsaEnumerateAccountsWithUserRight - return code is " + ret);
				
				objListofSteps.Add("Win32Sec.LsaEnumerateAccountsWithUserRight - Number of Accounts returned is " + count);
						
				if (ret != 0)
				{
					if (ret == STATUS_ACCESS_DENIED)
					{
						throw new UnauthorizedAccessException();
					}

					if (ret == STATUS_INSUFFICIENT_RESOURCES || ret == STATUS_NO_MEMORY)
					{
						throw new OutOfMemoryException();
					}

					throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
					
				}
				
				objListofSteps.Add(" Initializing LSA_ENUMERATION_INFORMATION for " + count + " nodes " + " ...");
									
				objListofSteps.Add(" .... LSA_ENUMERATION_INFORMATION Buffer Size is " + buffer);

				LSA_ENUMERATION_INFORMATION[] lsaInfo = new LSA_ENUMERATION_INFORMATION[count];
				
				//dadeniji 2016-11-03 11:56 AM
				//int elemOffs = 0;
				long elemOffs = 0;
				
				for (int i = 0; i < count; i++)										
				{
					
					objListofSteps.Add("(LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure - (int)buffer for " + i +  " " + buffer);
					
					//elemOffs = (int)buffer;
					elemOffs = (long)buffer;
					
					objListofSteps.Add("(LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure for " + i + " buffer is " + buffer);					
					
					lsaInfo[i] = (LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure
					(
						  (IntPtr)elemOffs
						, typeof(LSA_ENUMERATION_INFORMATION)
					);
					
					elemOffs += Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION));
				}

				
				objListofSteps.Add(" Completed LSA_ENUMERATION_INFORMATION for " + count + " nodes " + " ...");
				
				
				objListofSteps.Add("Win32Sec.LsaLookupSids - Invoking ");
				
				ret = Win32Sec.LsaLookupSids
						(
							  lsaHandle
							, lsaInfo.Length
							, buffer
							, out domains
							, out names
						);

				if (ret != 0)
				{
					
					if (ret == STATUS_ACCESS_DENIED)
					{
						throw new UnauthorizedAccessException();
					}

					if (ret == STATUS_INSUFFICIENT_RESOURCES || ret == STATUS_NO_MEMORY)
					{
						
						throw new OutOfMemoryException();
					}

					throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
				}
				
				objListofSteps.Add("Win32Sec.LsaLookupSids - Completed ");

				
				retNames = new string[count];
				currentDomain = new List<int>();
				domainCount = 0;

				lsaNames = new LSA_TRANSLATED_NAME[count];
				
				//elemOffs = (int)names;
				elemOffs = (long)names;
				
				//for (int i = 0, elemOffs = (int)names; i < count; i++)
				for (int i = 0; i < count; i++)
				{
					
					lsaNames[i] = (LSA_TRANSLATED_NAME)Marshal.PtrToStructure((LSA_HANDLE)elemOffs, typeof(LSA_TRANSLATED_NAME));
					
					elemOffs += Marshal.SizeOf(typeof(LSA_TRANSLATED_NAME));

					LSA_UNICODE_STRING name = lsaNames[i].Name;
					retNames[i] = name.Buffer.Substring(0, name.Length / 2);
					
					objListofSteps.Add(retNames[i]); 

					if (!currentDomain.Contains(lsaNames[i].DomainIndex))
					{
						
						domainCount = domainCount + 1;
						currentDomain.Add(lsaNames[i].DomainIndex);
					}
					//Error: not necessary to count domain names

				}

				string[] domainPtrNames = new string[count];

				LSA_REFERENCED_DOMAIN_LIST[] lsaDomainNames = new LSA_REFERENCED_DOMAIN_LIST[count];
				//Error: LSA_REFERENCED_DOMAIN_LIST is a structure, not an array

				//for (int i = 0, elemOffs = (int)domains; i < count; i++)
				//elemOffs = (int)domains;
				elemOffs = (long)domains;
				
				for (int i = 0; i < count; i++)
				//Error: not necessary
				{
					lsaDomainNames[i] = (LSA_REFERENCED_DOMAIN_LIST)Marshal.PtrToStructure
					(
						  (LSA_HANDLE)elemOffs
						, typeof(LSA_REFERENCED_DOMAIN_LIST)
					);
					
					elemOffs += Marshal.SizeOf(typeof(LSA_REFERENCED_DOMAIN_LIST));
					
				}

				LSA_TRUST_INFORMATION[] lsaDomainName = new LSA_TRUST_INFORMATION[count];
				
				string[] domainNames = new string[domainCount];

				//for (int i = 0, elemOffs = (int)lsaDomainNames[i].Domains; i < domainCount; i++)
				//elemOffs = (int)lsaDomainNames[0].Domains;	
				elemOffs = (long)lsaDomainNames[0].Domains;	
				for (int i = 0; i < domainCount; i++)
					
				{
					
					lsaDomainName[i] = (LSA_TRUST_INFORMATION)Marshal.PtrToStructure
										(
											  (LSA_HANDLE)elemOffs
											, typeof(LSA_TRUST_INFORMATION)
										);
					
					elemOffs += Marshal.SizeOf(typeof(LSA_TRUST_INFORMATION));

					LSA_UNICODE_STRING tempDomain = lsaDomainName[i].Name;
					
					/*
						
						//if(tempDomain.Buffer != null)
						//{
							domainNames[i] = tempDomain.Buffer.Substring(0, tempDomain.Length / 2);
						//}
					*/
					
					if(tempDomain.Buffer != null)
					{
						domainNames[i] = tempDomain.Buffer.Substring(0, tempDomain.Length / 2);
					}					

					
				}

				objListofSteps.Add("new string[count] - Instanicating new string[count]");
				
				domainUserName = new string[count];
				
				for (int i = 0; i < lsaNames.Length; i++)
				{
					
					objListofSteps.Add
						(
							"domainUserName[i] = domainNames[lsaNames[i].DomainIndex] \\ + retNames[i] "
							+ " - i " + i
							+ " - domainNames[lsaNames[i].DomainIndex] " + domainNames[lsaNames[i].DomainIndex]
							+ " - retNames[i] " + retNames[i]
						);
					
					domainUserName[i] = domainNames[lsaNames[i].DomainIndex] + "\\" + retNames[i];
				}
				
				objListofSteps.Add("Win32Sec.LsaFreeMemory - Initiating");

				Win32Sec.LsaFreeMemory(buffer);
				Win32Sec.LsaFreeMemory(domains);
				Win32Sec.LsaFreeMemory(names);
				
				objListofSteps.Add("Win32Sec.LsaFreeMemory - Completed");				

			}
			catch(Exception ex)
			{
				
				//Get a StackTrace object for the exception
				StackTrace st = new StackTrace(ex, true);

				//Get the first stack frame
				StackFrame frame = st.GetFrame(0);

				//Get the file name
				string fileName = frame.GetFileName();

				//Get the method name
				string methodName = frame.GetMethod().Name;

				//Get the line number from the stack frame
				int line = frame.GetFileLineNumber();

				//Get the column number
				int col = frame.GetFileColumnNumber();
				
				String strErr = null;
				
				strErr = ex.Message
							+ " - filename " + fileName				
							+ " - methodName " + methodName														
							+ " - Line Number " + line
							+ " - Column " + col
							;
				
				domainUserName = new string[1];
				
				domainUserName[0] = strErr;								
										
										
				objListofSteps.Add(strErr);
				
				domainUserName = objListofSteps.ToArray();
	
			}
			

			return (domainUserName);

		}
		
		
		
		
		
		public void AddPrivileges(string account, string privilege)
		{
			IntPtr pSid = GetSIDInformation(account);
			LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
			privileges[0] = InitLsaString(privilege);
			uint ret = Win32Sec.LsaAddAccountRights(lsaHandle, pSid, privileges, 1);

			if (ret == 0)
			{
				if (this._writeToConsole)
				{
					Console.WriteLine("Added: {0} to {1} successfully.", account, privilege);
				}
				return;
			}

			if (ret == STATUS_ACCESS_DENIED)
			{
				throw new UnauthorizedAccessException();
			}
			
			if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY))
			{
				throw new OutOfMemoryException();
			}
			
			throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
			
		}

		public void RemovePrivileges(string account, string privilege)
		{
			IntPtr pSid = GetSIDInformation(account);
			LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
			privileges[0] = InitLsaString(privilege);
			uint ret = Win32Sec.LsaRemoveAccountRights(lsaHandle, pSid, false, privileges, 1);

			if (ret == 0)
			{
				if (this._writeToConsole)
				{
					Console.WriteLine("Removed: {0} from {1} successfully.", account, privilege);
				}
				
				return;
			}
			
			if (ret == STATUS_ACCESS_DENIED)
			{
				throw new UnauthorizedAccessException();
			}
			
			if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY))
			{
				throw new OutOfMemoryException();
			}
			
			throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
		}
			

		 public bool WriteToConsole
		 {
			 set { this._writeToConsole = value; }
		 }
 
	}
	
    public class LsaWrapperCaller
    {
		
		//static String computerName = null;
		public static string computer { get; set; }
	
        public static void AddPrivileges(string account, string privilege)
        {
            using (LsaWrapper lsaWrapper = new LsaWrapper(computer))
            {
                lsaWrapper.AddPrivileges(account, privilege);
            }
        }
		
        public static void RemovePrivileges(string account, string privilege)
        {
            using (LsaWrapper lsaWrapper = new LsaWrapper(computer))
            {
                lsaWrapper.RemovePrivileges(account, privilege);
            }
        }

		public static string[] GetUsersWithPrivilege(string privilege)
        {
			
			string[] users = null;
			
            using (LsaWrapper lsaWrapper = new LsaWrapper(computer))
            {
                users = lsaWrapper.GetUsersWithPrivilege(privilege);
            }
			
			return (users);
        }
		
    }
	
 }