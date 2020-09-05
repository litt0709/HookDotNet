using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Management;
using System.Threading.Tasks;
using Newtonsoft.Json;
using HookingAssembly.DTO;
using static HookingAssembly.MinHook.NativeMethods;

namespace HookingAssembly
{
    //
    // An AppDomainManager derived class used to be loaded automatically.
    //
    public class CustomeAppDomainManager1 : AppDomainManager
    {
        private readonly HookWMI m_HookWMI = new HookWMI();
    }

    //
    // An implementation of .NET native code hocking against the ScanContent
    // method.
    //
    internal class HookWMI
    {
        private static readonly AssemblyLoadEventHandler s_EventHandler =
            new AssemblyLoadEventHandler(OnAssemblyLoad);

        //
        // Constructor. Starts monitoring of assembly loading to detect a
        // target assembly (ie, System.Management.Automation).
        //
        internal
        HookWMI(
            )
        {
            if (!AppDomain.CurrentDomain.IsDefaultAppDomain())
            {
                return;
            }

            AppDomain.CurrentDomain.AssemblyLoad += s_EventHandler;
            Console.WriteLine("[*] AssemblyLoad event handler registered.");
        }

        //
        // An assembly load event handler.
        //
        private
        static
        void
        OnAssemblyLoad(
            object Sender,
            AssemblyLoadEventArgs Args
            )
        {
            // Initialize
            const BindingFlags anyType = BindingFlags.Static |
                                      BindingFlags.Instance |
                                      BindingFlags.Public |
                                      BindingFlags.NonPublic;
 
            // Hook change info
            string assemblyName = Args.LoadedAssembly.GetName().Name;
            Console.WriteLine("[*] Loading assembly " + assemblyName);

            if (assemblyName != "System.Net.Http")
            {
                return;
            }
           
            if (assemblyName == "System.Net.Http")
            {
                // Hook WMI Hanlder
                AppDomain.CurrentDomain.AssemblyLoad -= s_EventHandler;
                Assembly smAssembly = Args.LoadedAssembly;

                // For Debug
                //Debugger.Launch();

                // hook 1
                var targetMethodType = new Type[] { typeof(string) };
                var handlerMethodType = new Type[] { typeof(string) };
                var trampolineMethodType = new Type[] { typeof(string) };

                Type targetMethodClass = smAssembly.GetType("System.Net.Http.HttpClient");
                Type handlerMethodClass = typeof(HookWMI);
                Type trampolineMethodClass = typeof(HookWMI);

                MethodInfo target = targetMethodClass.GetMethod("GetStringAsync",
                                                            anyType,
                                                            null,
                                                            targetMethodType,
                                                            null);
                MethodInfo hookHandler = handlerMethodClass.GetMethod(
                                                        "GetStringAsyncHandler",
                                                        anyType,
                                                        null,
                                                        handlerMethodType,
                                                        null);
                MethodInfo trampoline = trampolineMethodClass.GetMethod(
                                                  "GetStringAsyncTrampoline",
                                                  anyType,
                                                  null,
                                                  trampolineMethodType,
                                                  null);

                RuntimeHelpers.PrepareMethod(target.MethodHandle);
                RuntimeHelpers.PrepareMethod(hookHandler.MethodHandle);
                RuntimeHelpers.PrepareMethod(trampoline.MethodHandle);

                IntPtr targetAddr = target.MethodHandle.GetFunctionPointer();
                IntPtr hookHandlerAddr = hookHandler.MethodHandle.GetFunctionPointer();
                IntPtr trampolineAddr = trampoline.MethodHandle.GetFunctionPointer();

                if (!MinHook.InstallHook(targetAddr, hookHandlerAddr, trampolineAddr))
                {
                    return;
                }

                Console.WriteLine("[*] The SysNet method has been hooked.");
            }
        }

        public
        Task<string>
        GetStringAsyncHandler(string requestUri)
        {
            if (requestUri.Contains("tsm.pimbot.net"))
            {
                // get datasend
                string dataLog = this.GetType().GetProperty("DefaultRequestHeaders").GetValue(this, null).ToString();
                string encryptText = dataLog.Replace("DataLog:", "").Trim();

                // decrypt datasend
                string secretKey = "~)!cbe#14dBNa12^hc#dha)#DAc";
                string plaintext = Encryptor.DecryptString(secretKey, encryptText);

                // create data receive
                string dataget = "";
                // case first login
                if (plaintext.Contains("PIM"))
                {
                    PimLogin pimLogin = new PimLogin();
                    pimLogin.ID = 2596;
                    pimLogin.urlUpdate = "";
                    pimLogin.isNewVersion = 0;
                    pimLogin.isMustUpdate = "";
                    pimLogin.NgayHetHan = 72686.0;
                    pimLogin.DT = DateTime.Now.ToOADate();
                    pimLogin.isFull = true;
                    pimLogin.isV = false;
                    pimLogin.SoLuongTaiKhoan = 99;
                    dataget = JsonConvert.SerializeObject(pimLogin);
                }
                // case login game
                if (plaintext.Contains("LOGIN"))
                {
                    GameLogin gameLogin = new GameLogin();
                    gameLogin.rs = "";
                    gameLogin.rsPing = "";

                    gameLogin.msg = "";
                    gameLogin.isLoginTrucTiep = true;
                    gameLogin.ua = "TS%20Online%20Mobile/10 CFNetwork/1121.2.2 Darwin/19.2.0";
                    gameLogin.url = "https://api.dzogame.vn/SDK/v1/Authen/loginDzoID";
                    gameLogin.urlPing = "https://api.dzogame.vn/SDK/v1/Authen/pingToken";

                    gameLogin.DeviceId = "bdca5868d329615cd6114a51e0ad19d1";
                    gameLogin.DT = DateTime.Now.ToOADate();
                    dataget = JsonConvert.SerializeObject(gameLogin);
                }
         
           
                // encrypt data receive
                dataget = Encryptor.EncryptString(secretKey, dataget);
                string response = "\"" + dataget + "\"";

                // return
                return Task.Run(() =>(response));
            }

            Task<string> result = GetStringAsyncTrampoline(requestUri);
            return result;
        }

        private void ReplaceAll(string[] items, string oldValue, string newValue)
        {
            for (int index = 0; index < items.Length; index++)
                if (items[index] == oldValue)
                    items[index] = newValue;
        }

        // original function
        [MethodImpl(MethodImplOptions.NoInlining)]
        public
        Task<string>
        GetStringAsyncTrampoline(string requestUri)
        {
            Trace.Assert(false);
            throw new Exception("It is a bug. Fix it bro!");
        }

   
    }


    #region MinHook specific. You very likely need your code for hooking.
    internal static class MinHook
    {
        //
        // Helper function to install hook using MinHook.
        //
        internal
        static
        bool
        InstallHook(
            IntPtr TargetAddr,
            IntPtr HookHandlerAddr,
            IntPtr TrampolineAddr
            )
        {
            //
            // This code expects either MinHook.x86.dll or MinHook.x64.dll is
            // located in any of the DLL search path. Such as the current folder
            // and %PATH%.
            //
            string architecture = (IntPtr.Size == 4) ? "x86" : "x64";
            string dllPath = "MinHook." + architecture + ".dll";
            IntPtr moduleHandle = LoadLibrary(dllPath);
            if (moduleHandle == IntPtr.Zero)
            {
                Console.WriteLine("[-] An inline hook DLL not found. Did you locate " +
                                  dllPath + " under the DLL search path?");
                return false;
            }

            var MH_Initialize = GetExport<MH_InitializeType>(moduleHandle, "MH_Initialize");
            var MH_CreateHook = GetExport<MH_CreateHookType>(moduleHandle, "MH_CreateHook");
            var MH_EnableHook = GetExport<MH_EnableHookType>(moduleHandle, "MH_EnableHook");


            MH_STATUS status = MH_Initialize();
            //Trace.Assert(status == MH_STATUS.MH_OK);

            //
            // Modify the target method to jump to the HookHandler method. The
            // original receives an address of trampoline code to call the
            // original implementation of the target method.
            //
            status = MH_CreateHook(TargetAddr, HookHandlerAddr, out IntPtr original);
            //Trace.Assert(status == MH_STATUS.MH_OK);

            //
            // Modify the Trampoline method to jump to the original
            // implementation of the target method.
            //
            status = MH_CreateHook(TrampolineAddr, original, out _);

            //Trace.Assert(status == MH_STATUS.MH_OK);
            //
            // Commit and activate the above two hooks.
            //
            status = MH_EnableHook(MH_ALL_HOOKS);
            //Trace.Assert(status == MH_STATUS.MH_OK);

            return true;
        }

        //
        // Helper function to resolve an export of a DLL.
        //
        private
        static
        ProcType
        GetExport<ProcType>(
            IntPtr ModuleHandle,
            string ExportName
            ) where ProcType : class
        {
            //
            // Get a function pointer, convert it to delegate, and return it as
            // a requested type.
            //
            IntPtr pointer = GetProcAddress(ModuleHandle, ExportName);
            if (pointer == IntPtr.Zero)
            {
                return null;
            }

            Delegate function = Marshal.GetDelegateForFunctionPointer(
                                                            pointer,
                                                            typeof(ProcType));
            return function as ProcType;
        }

        [SuppressUnmanagedCodeSecurity]
        internal static class NativeMethods
        {
            [DllImport("kernel32.dll",
                        EntryPoint = "LoadLibraryW",
                        SetLastError = true,
                        CharSet = CharSet.Unicode)]
            internal
            static
            extern
            IntPtr
            LoadLibrary(
                string FileName
                );

            [DllImport("kernel32.dll",
                        EntryPoint = "GetProcAddress",
                        SetLastError = true,
                        CharSet = CharSet.Ansi,
                        BestFitMapping = false)]
            internal
            static
            extern
            IntPtr
            GetProcAddress(
                IntPtr Module,
                string ProcName
                );

            //
            // MinHook specific.
            //
            internal static IntPtr MH_ALL_HOOKS = IntPtr.Zero;
            internal enum MH_STATUS
            {
                MH_OK = 0,
            }

            [UnmanagedFunctionPointer(CallingConvention.Winapi)]
            internal
            delegate
            MH_STATUS
            MH_InitializeType(
                );

            [UnmanagedFunctionPointer(CallingConvention.Winapi)]
            internal
            delegate
            MH_STATUS
            MH_CreateHookType(
                IntPtr Target,
                IntPtr Detour,
                out IntPtr Original
                );

            [UnmanagedFunctionPointer(CallingConvention.Winapi)]
            internal
            delegate
            MH_STATUS
            MH_EnableHookType(
                IntPtr Target
                );
        }
    }
    #endregion
}
