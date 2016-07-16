using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections.Specialized;
using VMware.Vim;
//using VMware.Vim.Client;
using System.Security;
using System.IO;
using System.Reflection;
using System.Web.Services.Protocols;
using System.Web.Services;
using Microsoft.Web.Services3;

/*  Requires namespace VMware.Vim and VimApi
 *  Requires VMware.Vim.dll
 *  Requires VMware.VimAutomation.Logging.SoapInterceptor.dll
 *  Requires Vim25Service.dll
 */
namespace VMWareChatter {
   public class vCenterCommunicator : IDisposable {    
      VMware.Vim.VimClient vSphereClient = new VMware.Vim.VimClient();
      VMware.Vim.ServiceContent vConnection = null;
      VMware.Vim.UserSession thisSession = null;
      VimApiAccess vimApiAccess = null;
      FileStream logWriter = null;
      public static object m_lock = "";
      private string m_UserNameUsed;
      private SecureString m_PasswordUsed;

      public static string AssemblyDirectory {
         get {
            string codeBase = Assembly.GetExecutingAssembly().CodeBase;
            UriBuilder uri = new UriBuilder(codeBase);
            string path = Uri.UnescapeDataString(uri.Path);
            return Path.GetDirectoryName(path);
         }
      }
      public bool IsConnected {
         get {
            if (vConnection == null || thisSession == null)
               return false;
            return true;            
         }
      }
      /// <summary>
      /// Used to talk to and automate an ESXi environment
      /// </summary>
      /// <param name="hostName">The vCenter DNS hostname or IP-address it can be contacted by</param>
      /// <param name="userName">Username as part of needed credential for access</param>
      /// <param name="password">Password as part of needed credential for access</param>
      /// <param name="domain">Domain as part of needed credential for access</param>
      public vCenterCommunicator(String hostName, String userName, SecureString password, String domain) {
         lock (m_lock) {
            logWriter = new FileStream(Path.Combine(vCenterCommunicator.AssemblyDirectory, "VMWareChatter-CrashLogs.log"), FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
         }
         try {
            //Fetch information and collect them in a representative object:
            vConnection = vSphereClient.Connect("https://" + hostName + "/sdk");
            if (!String.IsNullOrEmpty(domain)) userName = domain + "\\" + userName;
            thisSession = vSphereClient.Login(userName, System.Runtime.InteropServices.Marshal.PtrToStringAuto(System.Runtime.InteropServices.Marshal.SecureStringToBSTR(password)));
            vimApiAccess = new VimApiAccess(vConnection);
            vimApiAccess.Connect("https://" + hostName + "/sdk", userName, System.Runtime.InteropServices.Marshal.PtrToStringAuto(System.Runtime.InteropServices.Marshal.SecureStringToBSTR(password)));
         }
         catch (Exception ex) {
            lock (m_lock) {
               WriteLogText(logWriter, "Error: " + ex.Message + ", after connecting with username: " + userName + ", host: " + hostName);
            }
            throw;
         }
         m_UserNameUsed = userName;
         m_PasswordUsed = password;
      }
      ~vCenterCommunicator() {
         this.Dispose();
      }
      public void Dispose() {
         try {
            vSphereClient.Logout();
            vSphereClient.Disconnect();
            lock (m_lock) {
               logWriter.Close();
               logWriter.Dispose();
            }
            vimApiAccess.Disconnect();
         }
         catch {
            //Do nothing
         }
      }
      private static void WriteLogText(FileStream fs, string value) {
         value = Environment.NewLine + DateTime.Now.ToString() + " - " + value;
         byte[] info = new UTF8Encoding(true).GetBytes(value);
         fs.Write(info, 0, info.Length);
      }
      public void ShutdownAllHosts() {
         this.GetHostSystems().ForEach(host => host.ShutdownHost(true));
      }
      /// <summary>
      /// Get a list of wrappers that sum up information about the virtual machines we are looking for
      /// </summary>
      /// <param name="guestNameFilter">The selected VM name filter to find, empty filer means all</param>
      /// <returns></returns>
      public List<VirtualMachineWrapper> GetVirtualMachines(String guestNameFilter) {
         /*if (String.IsNullOrEmpty(guestNameFilter)) {
            return new List<VirtualMachineWrapper>();
         }*/
         var filter = new NameValueCollection();
         if(!String.IsNullOrEmpty(guestNameFilter))
            filter.Add("name", guestNameFilter);
         List<VMware.Vim.VirtualMachine> vms = new List<VMware.Vim.VirtualMachine>();
         try {
            vSphereClient.FindEntityViews(typeof(VMware.Vim.VirtualMachine), null, (!String.IsNullOrEmpty(guestNameFilter) ? filter : null), null).ForEach(vm => vms.Add((VMware.Vim.VirtualMachine)vm));
         }
         catch (Exception e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
         List<VirtualMachineWrapper> virtualMachineWrappers = new List<VirtualMachineWrapper>();
         GuestDiskInfoWrapper[] guestDisks = null;
         foreach (VirtualMachine vm in vms) {
            if (vm.Guest.Disk != null) {
               guestDisks = vm.Guest.Disk.Where(disk => disk != null).Select(disk => (GuestDiskInfoWrapper)disk).ToArray();
            }
            virtualMachineWrappers.Add(
               new VirtualMachineWrapper() {
                  NumMksConnections = vm.Summary.Runtime.NumMksConnections,
                  PowerState = vm.Summary.Runtime.PowerState == VMware.Vim.VirtualMachinePowerState.poweredOn,
                  IpAddress = String.IsNullOrEmpty(vm.Summary.Guest.IpAddress) ? String.Empty : vm.Summary.Guest.IpAddress,
                  HostName = String.IsNullOrEmpty(vm.Summary.Guest.HostName) ? String.Empty : vm.Summary.Guest.HostName,
                  ToolsRunningStatus = String.IsNullOrEmpty(vm.Summary.Guest.ToolsRunningStatus) ? String.Empty : vm.Summary.Guest.ToolsRunningStatus,
                  ToolsVersionStatus = String.IsNullOrEmpty(vm.Summary.Guest.ToolsVersionStatus) ? String.Empty : vm.Summary.Guest.ToolsVersionStatus,
                  NumCpu = vm.Summary.Config.NumCpu,
                  Name = String.IsNullOrEmpty(vm.Summary.Config.Name) ? String.Empty : vm.Summary.Config.Name,
                  MemorySizeMB = vm.Summary.Config.MemorySizeMB,
                  NumVirtualDisks = vm.Summary.Config.NumVirtualDisks,
                  Disk = guestDisks
               }
            );
         }
         return virtualMachineWrappers;
      }
      /// <summary>
      /// Get a wrapper that sums up information about the virtual machine we are looking for
      /// </summary>
      /// <param name="guestNameFilter">The selected VM to find</param>
      /// <returns></returns>
      public VirtualMachineWrapper GetVirtualMachine(String guestNameFilter) {
         if (String.IsNullOrEmpty(guestNameFilter)) {
            return new VirtualMachineWrapper();
         }
         var filter = new NameValueCollection();
         filter.Add("name", guestNameFilter);
         VirtualMachine vm = null;
         try {
            vm = (VirtualMachine)vSphereClient.FindEntityView(typeof(VirtualMachine), null, filter, null);
         }
         catch (Exception e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
         GuestDiskInfoWrapper[] guestDisks = null;
         if (vm != null && vm.Guest != null && vm.Guest.Disk != null) {
            guestDisks = vm.Guest.Disk.Where(disk => disk != null).Select(disk => (GuestDiskInfoWrapper)disk).ToArray();
         }
         return vm != null ? new VirtualMachineWrapper() {
            NumMksConnections = vm.Summary.Runtime.NumMksConnections,
            PowerState = vm.Summary.Runtime.PowerState == VMware.Vim.VirtualMachinePowerState.poweredOn,
            IpAddress = String.IsNullOrEmpty(vm.Summary.Guest.IpAddress) ? String.Empty : vm.Summary.Guest.IpAddress,
            HostName = String.IsNullOrEmpty(vm.Summary.Guest.HostName) ? String.Empty : vm.Summary.Guest.HostName,
            ToolsRunningStatus = String.IsNullOrEmpty(vm.Summary.Guest.ToolsRunningStatus) ? String.Empty : vm.Summary.Guest.ToolsRunningStatus,
            ToolsVersionStatus = String.IsNullOrEmpty(vm.Summary.Guest.ToolsVersionStatus) ? String.Empty : vm.Summary.Guest.ToolsVersionStatus,
            NumCpu = vm.Summary.Config.NumCpu,
            Name = String.IsNullOrEmpty(vm.Summary.Config.Name) ? String.Empty : vm.Summary.Config.Name,
            MemorySizeMB = vm.Summary.Config.MemorySizeMB,
            NumVirtualDisks = vm.Summary.Config.NumVirtualDisks,
            Disk = guestDisks
         } : new VirtualMachineWrapper();
      }
      private List<VirtualMachine> GetVirtualMachines() {
         List<EntityViewBase> entityViews = null;
         List<VirtualMachine> vms = new List<VirtualMachine>();
         try {
            entityViews = vSphereClient.FindEntityViews(typeof(VirtualMachine), null, null, null).ToList();
            foreach (EntityViewBase ent in entityViews) {
               vms.Add((VirtualMachine)ent);
            }
         }
         catch (Exception e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
         return vms;
      }
      /// <summary>
      /// Get number of console sessions on a selected VM
      /// </summary>
      /// <param name="guestNameFilter">The selected VM</param>
      /// <returns></returns>
      public int GetVMNumMksConnections(String guestNameFilter) {
         if (String.IsNullOrEmpty(guestNameFilter)) {
            return 0;
         }
         var filter = new NameValueCollection();
         filter.Add("name", guestNameFilter);
         VirtualMachine vm = null;
         try {
            vm = (VirtualMachine)vSphereClient.FindEntityView(typeof(VirtualMachine), null, filter, null);
         }
         catch (Exception e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
         return vm != null ? vm.Summary.Runtime.NumMksConnections : 0;
      }
      public bool GetVMPowerState(String guestNameFilter) {
         var filter = new NameValueCollection();
         filter.Add("name", guestNameFilter);
         VirtualMachine vm = null;
         try {
            vm = (VirtualMachine)vSphereClient.FindEntityView(typeof(VirtualMachine), null, filter, null);
         }
         catch (Exception e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
         return vm != null ? vm.Summary.Runtime.PowerState == VMware.Vim.VirtualMachinePowerState.poweredOn : false;
      }
      /// <summary>
      /// Sets a new powerstate
      /// </summary>
      /// <param name="guestNameFilter">The guest to power on or off</param>
      /// <param name="powerState">True to power on, false to power off</param>
      public void SetVMPowerState(String guestNameFilter, bool powerState) {
         var filter = new NameValueCollection();
         filter.Add("name", guestNameFilter);
         VirtualMachine vm = null;
         try {
            vm = (VirtualMachine)vSphereClient.FindEntityView(typeof(VirtualMachine), null, filter, null);
         }
         catch (Exception e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
         try {
            if (powerState) {
               HostSystem host = GetHostSystems().FirstOrDefault();
               if (host != null) {
                  vm.PowerOnVM_Task(host.MoRef);
               }
            }
            else {
               vm.PowerOffVM();
            }
         }
         catch (Exception e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
      }
      /// <summary>
      /// Sets a new powerstate via the VMware toold and the OS
      /// </summary>
      /// <param name="guestNameFilter">The guest to power on or off via OS</param>
      /// <param name="powerState">True to power on, false to power off</param>
      public void SetVMGuestOSPowerState(String guestNameFilter, bool powerState) {
         var filter = new NameValueCollection();
         filter.Add("name", guestNameFilter);
         VirtualMachine vm = null;
         try {
            vm = (VirtualMachine)vSphereClient.FindEntityView(typeof(VirtualMachine), null, filter, null);
         }
         catch (Exception e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
         try {
            if (powerState) {
               HostSystem host = GetHostSystems().FirstOrDefault();
               if (host != null) {
                  vm.PowerOnVM_Task(host.MoRef);
               }
            }
            else {
               vm.ShutdownGuest();
            }
         }
         catch (Exception e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
      }

      /// <summary>
      ///  Gets information to start a VMRC session to virtual machines
      /// </summary>
      /// <param name="guestNameFilter">Name of guest that you want to fetch information about</param>
      public OrderedDictionary GetVMRCLogonInfo(String guestNameFilter, string userName) {
         OrderedDictionary LogonInfoDictionary = new OrderedDictionary();
         var filter = new NameValueCollection();
         filter.Add("name", guestNameFilter);
         IList<EntityViewBase> vms = vSphereClient.FindEntityViews(typeof(VirtualMachine), null, filter, null);

         if (vms != null) {
            foreach (VMware.Vim.EntityViewBase tmp in vms) {
               VirtualMachine vm = (VirtualMachine)tmp;
               string vmkid = vm.Summary.Vm.Value;
               string vmName = vm.Name;
               int numConnections = vm.Summary.Runtime.NumMksConnections;
               string cloneTicket = GetCloneTicket();
               VMware.Vim.SessionManagerLocalTicket localTicket = null;
               try {
                  localTicket = GetLocalTicket(userName);
               }
               catch {
                  throw;
               }
               LogonInfoDictionary.Add(vmName, new VmrcLogonInfo() { VmkID = vmkid, LocalTicket = localTicket, CloneTicket = cloneTicket, ConsoleConnections = numConnections });
            }
         }
         return LogonInfoDictionary;
      }
      private ServiceInstance GetServiceInctance() {
         VMware.Vim.ManagedObjectReference _svcRef = new VMware.Vim.ManagedObjectReference() { Type = "ServiceInstance", Value = "ServiceInstance" };
         ServiceInstance _service = new ServiceInstance(vSphereClient, _svcRef);
         return _service;
      }
      private LicenseManager GetLicenseManager() {
         LicenseManager licenseManager = null;
         try {
            VMware.Vim.ServiceContent _sic = GetServiceInctance().RetrieveServiceContent();
            licenseManager = (LicenseManager)vSphereClient.GetView(_sic.LicenseManager, null);
         } catch {
            throw;
         }
         return licenseManager;
      }
      private SessionManager GetSessionManager() {
         SessionManager sessionManager = null;
         try {
            VMware.Vim.ServiceContent _sic = GetServiceInctance().RetrieveServiceContent();
            sessionManager = (SessionManager)vSphereClient.GetView(_sic.SessionManager, null);
         }
         catch {
            throw;
         }
         return sessionManager;
      }
      private AuthorizationManager GetAuthorizationManager() {
         AuthorizationManager authorizationManager = null;
         try {
            VMware.Vim.ServiceContent _sic = GetServiceInctance().RetrieveServiceContent();
            authorizationManager = (AuthorizationManager)vSphereClient.GetView(_sic.AuthorizationManager, null);
         }
         catch {
            throw;
         }
         return authorizationManager;
      }
      /// <summary>
      /// Check if a host has a access right assigned for the current session
      /// NB! Function fails with: The operation is not supported on the object
      /// </summary>
      /// <param name="host">HostSystem</param>
      /// <param name="privilegeID">new string[] { "VirtualMachine.Interact.ConsoleInteract" }</param>
      /// <returns>Success state</returns>
      public bool CheckAccessRightOnHost(HostSystem host, string[] privilegeID) {
         bool status = true;
         AuthorizationManager authManager = GetAuthorizationManager();
         try {
            foreach (bool x in authManager.HasPrivilegeOnEntity(host.MoRef, thisSession.Key, privilegeID).ToList()) {
               status = (x == false ? false : status);
            }
         }
         catch {
            throw;
         }
         return status;
      }
      /// <summary>
      /// Get a list of all hosts
      /// </summary>
      /// <returns>List of all ESXi hosts</returns>
      public List<HostSystem> GetHostSystems() {
         List<HostSystem> hostSystems = new List<HostSystem>();
         try {
            Datacenter dataCenter = (Datacenter)vSphereClient.FindEntityView(typeof(Datacenter), null, null, null);
            Folder folder = (Folder)vSphereClient.GetView(dataCenter.HostFolder, null);
            foreach (VMware.Vim.ManagedObjectReference mObjR in folder.ChildEntity.Where(x => x.Type == "ComputeResource")) {
               ComputeResource computeResource = (ComputeResource)vSphereClient.GetView(mObjR, null);
               foreach (VMware.Vim.ManagedObjectReference hostRef in computeResource.Host) {
                  hostSystems.Add((HostSystem)vSphereClient.GetView(hostRef, null));
               }
            }
         }
         catch {
            throw;
         }
         return hostSystems;
      }
      /// <summary>
      /// Get a list of all hosts filtered by name
      /// </summary>
      /// <param name="hostName">name to filter on, do not use wildcards</param>
      /// <returns>List of all ESXi hosts</returns>
      public List<HostSystem> GetHostSystems(string hostFilterName) {
         List<HostSystem> hostSystems = new List<HostSystem>();
         try {
            Datacenter dataCenter = (Datacenter)vSphereClient.FindEntityView(typeof(Datacenter), null, null, null);
            Folder folder = (Folder)vSphereClient.GetView(dataCenter.HostFolder, null);
            foreach (VMware.Vim.ManagedObjectReference mObjR in folder.ChildEntity.Where(x => x.Type == "ComputeResource")) {
               ComputeResource computeResource = (ComputeResource)vSphereClient.GetView(mObjR, null);
               foreach (VMware.Vim.ManagedObjectReference hostRef in computeResource.Host) {
                  HostSystem hostSystem = (HostSystem)vSphereClient.GetView(hostRef, null);
                  if(hostSystem.Name.Contains(hostFilterName) || hostSystem.Name.Equals(hostFilterName)) {
                     hostSystems.Add(hostSystem);
                  }                  
               }
            }
         }
         catch {
            throw;
         }
         return hostSystems;
      }
      /// <summary>
      /// Downloads a file from a datastore
      /// </summary>
      /// <param name="hostName">Name of host</param>
      /// <param name="dataStoreName">datastore</param>
      /// <param name="path">[datastore] /folder/file.txt</param>
      public void DownloadDataStoreFile(string hostName, string dataStoreName, string path) {
         throw new NotImplementedException();
         //See
         //https://www.vmware.com/support/developer/vc-sdk/visdk25pubs/ReferenceGuide/vim.FileManager.html
         //This is possible to implement, see GetVMFiles.cs in Samples2008

      }
      /// <summary>
      /// Finds files we search for
      /// </summary>
      /// <param name="hostName">The host we want to fetch from</param>
      /// <param name="dataStoreName">The datastore we want to fetch</param>
      /// <param name="path">The path to search of type: [datastore] /folder/file</param>
      /// <returns>List of paths</returns>
      public String[] SearchDatastoreForFile(string hostName, string dataStoreName, string path) {
         Datastore ds = this.GetHostDatastore(hostName, dataStoreName);
         HostDatastoreBrowser hdsb = (HostDatastoreBrowser)vSphereClient.GetView(ds.Browser, null);
         VMware.Vim.FileQueryFlags fqf = new VMware.Vim.FileQueryFlags() { FileOwner = false, FileSize = true, FileType = false, Modification = true };

         VMware.Vim.HostDatastoreBrowserSearchSpec searchSpec = new VMware.Vim.HostDatastoreBrowserSearchSpec() {
            SearchCaseInsensitive = true,
            Query = new VMware.Vim.FileQuery[] {
               new VMware.Vim.FolderFileQuery() { }
            },
            Details = fqf,
            SortFoldersFirst = false,
         };
         VMware.Vim.HostDatastoreBrowserSearchResults hdbsr = hdsb.SearchDatastore(path, searchSpec);
         return hdbsr.File.AsParallel<VMware.Vim.FileInfo>().Select(file => file.Path).ToArray();
      }
      /// <summary>
      /// Fetches a specified datastore from a VMWare ESXi host
      /// </summary>
      /// <param name="hostName">The host we want to fetch from</param>
      /// <param name="dataStoreName">The datastore we want to fetch of type: [datastore] /folder/file</param>
      /// <returns>The datastore we want</returns>
      public Datastore GetHostDatastore(string hostName, string dataStoreName) {
         HostSystem theHost = this.GetHostSystems().Where(host => host.Name == hostName).FirstOrDefault();
         foreach (VMware.Vim.ManagedObjectReference mob in theHost.Datastore) {
            Datastore currentDatastore = (Datastore)vSphereClient.GetView(mob, null);
            if (currentDatastore.Name.ToLower() == dataStoreName.ToLower()) {
               return currentDatastore;
            }
         }
         return null;     
      }
      /// <summary>
      /// Fetches all datastores from a VMWare ESXi host
      /// </summary>
      /// <param name="hostName">The host we want to fetch from</param>
      /// <returns>List of all the datastores</returns>
      public List<Datastore> GetHostDatastores(string hostName) {
         List<Datastore> datastores = new List<Datastore>();
         HostSystem theHost = this.GetHostSystems().Where(host => host.Name == hostName).FirstOrDefault();
         foreach (VMware.Vim.ManagedObjectReference mob in theHost.Datastore) {
            Datastore currentDatastore = (Datastore)vSphereClient.GetView(mob, null);
            datastores.Add(currentDatastore);
         }
         return datastores;
      }
      /// <summary>
      /// Check if a license feature is present. 
      /// </summary>
      /// <param name="featureName">Name of the feature</param>
      /// <returns>True or false</returns>
      public bool CheckLicenseFeature(string featureName) {
         try {
            List<VMware.Vim.KeyValue> keyValueList = GetLicenseManager().Licenses[0].Properties.Where(x => x.Key == "feature").Select(x => x.Value).ToList().Cast<VMware.Vim.KeyValue>().ToList().Where(keyValue => keyValue.Value.ToString().ToLower() == featureName.ToLower()).ToList();
            if (keyValueList != null && keyValueList.Count > 0) {
               return true;
            }
         } catch(VimException ex) {
            if (ex.MethodFault.GetType() == typeof(VMware.Vim.NoPermission)) {
               WriteLogText(logWriter, ex.Message.ToString());
               return false;
               /*
               lock (m_lock) {
                  string message = "Error at CheckLicenseFeature() of type " + ex.MethodFault.GetType() + ": " + ex.Message + Environment.NewLine + ex.InnerException + ", trace: " + ex.StackTrace;
                  if (ex.MethodFault.GetType() == typeof(NoPermission)) {
                     message += Environment.NewLine + "    Username that was used in attempting to perform the action was '" + m_UserNameUsed + "'";
                  }
                  WriteLogText(logWriter, message);
               } 
               */
            } else {
               throw;
            }
         }
         return false;
      }
      /// <summary>
      /// Update the license where the client is connected
      /// </summary>
      /// <param name="license">License as string</param>
      /// <returns>True or false, for success or not</returns>
      public bool UpdateLicense(string license) {
         VMware.Vim.KeyValue DummyKey = new VMware.Vim.KeyValue() { Key = "DummyKey", Value = "DummyValue" };
         VMware.Vim.KeyValue[] DummyArray = new VMware.Vim.KeyValue[1] { DummyKey };
         VMware.Vim.LicenseManagerLicenseInfo lInfo = GetLicenseManager().UpdateLicense(license, DummyArray);
         if (lInfo == null) return false;
         return lInfo.LicenseKey.ToUpper() == license.ToUpper();
      }
      /// <summary>
      /// Gets a clone ticket to use for one time authentication
      /// </summary>
      /// <returns>Clone ticket as a string</returns>
      public string GetCloneTicket() {
         return GetSessionManager().AcquireCloneTicket();
      }
      /// <summary>
      /// Get a local ticket. It will be created on the host and won't be available to us.
      /// You can find it under /var/run/vmware-hostd-ticket/ for a few seconds, it contains the password.
      /// </summary>
      /// <param name="userName">Username to create a one time ticket for</param>
      /// <returns>One time ticket object</returns>
      public VMware.Vim.SessionManagerLocalTicket GetLocalTicket(string userName) {
         return GetSessionManager().AcquireLocalTicket(userName);
      }
      /// <summary>
      /// Disconnect all sessions that are running where the client is connected.
      /// </summary>
      public void DisconnectAllSessions() {
         SessionManager sessionManager = GetSessionManager();
         string[] sessionId = sessionManager.SessionList.Where(x => x.Key != sessionManager.CurrentSession.Key).Select(key => key.Key).ToArray();
         try {
            if (sessionId.Count() > 0)
               sessionManager.TerminateSession(sessionId);
         }
         catch (Exception e) {
            if (e.Message.ToLower() != "a specified parameter was not correct") {
               throw;
            }
         }
      }
      /// <summary>
      /// Disconnects all sessions that is marked as last active more then x minutes ago
      /// </summary>
      /// <param name="Minutes">Amount of minutes</param>
      public void DisconnectSessions(int Minutes) {
         SessionManager sessionManager = GetSessionManager();
         string[] sessionId = sessionManager.SessionList.Where(x => x.Key != sessionManager.CurrentSession.Key && (DateTime.Now - x.LastActiveTime).Minutes > Minutes).Select(key => key.Key).ToArray();
         try {
            if (sessionId.Count() > 0)
               sessionManager.TerminateSession(sessionId);
         }
         catch (Exception e) {
            if (e.Message.ToLower() != "a specified parameter was not correct") {
               throw;
            }
         }
      }
      /// <summary>
      /// Disconnects all sessions by a specified user that is marked as last acitve more then x minutes ago
      /// </summary>
      /// <param name="Minutes">Amount of minutes</param>
      /// <param name="UserName">Username of the user to diconnect</param>
      public void DisconnectSessions(int Minutes, string UserName) {
         SessionManager sessionManager = GetSessionManager();
         string[] sessionId = sessionManager.SessionList.Where(
            x => x.Key != sessionManager.CurrentSession.Key
            && (DateTime.Now - x.LastActiveTime).Minutes > Minutes
            && x.UserName == UserName
            //The following line is to avoid disconnecting sessions that appear to have been opened in the year 1970 something. 
            //This is a VMware bug and is fixed by patching the host:
            && x.LastActiveTime.Year != 1970).Select(key => key.Key).ToArray();
         try {
            if (sessionId.Count() > 0)
               sessionManager.TerminateSession(sessionId);
         }
         catch (Exception e) {
            if (e.Message.ToLower() != "a specified parameter was not correct") {
               throw (e);
            }
         }
      }
      /// <summary>
      /// Removes a standard port group from a host
      /// </summary>
      /// <param name="host"></param>
      /// <param name="portGroupName"></param>
      public void RemovePortGroup(VMware.Vim.HostSystem host, string portGroupName) {
         try { 
            if (host != null) {
               VMware.Vim.HostConfigManager configMgr = host.ConfigManager;
               vimApiAccess.RemovePortGroup(configMgr, portGroupName);
            }
         }
         catch (VimException e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         } catch (Exception e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
      }
      /// <summary>
      /// Creates a standard port group on a host
      /// </summary>
      /// <param name="host"></param>
      /// <param name="portGroupName"></param>
      /// <param name="vSwitchName"></param>
      public void CreatePortGroup(VMware.Vim.HostSystem host, string portGroupName, string vSwitchName) {
         try { 
            if (host != null) {
               VMware.Vim.HostConfigManager configMgr = host.ConfigManager;
               vimApiAccess.CreatePortGroup(configMgr, portGroupName, vSwitchName);
            }
         } catch(VimException e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         } catch (Exception e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
      }
      public void AddNetworkAdapterToVM(string vmName, string networkName) {
         try { 
            VirtualMachine vm = this.GetVirtualMachines().Where(_vm => _vm.Name == vmName).FirstOrDefault();
            if (vm != null) {
               Network vNic = new Network(vSphereClient, vm.Runtime.Host);

               VirtualDeviceConfigSpec nicSpec = new VirtualDeviceConfigSpec();
               if (networkName != null) {
                  nicSpec.Operation = VirtualDeviceConfigSpecOperation.add;
                  VirtualEthernetCard nic = new VirtualVmxnet();
                  VirtualEthernetCardNetworkBackingInfo nicBacking = new VirtualEthernetCardNetworkBackingInfo();
                  nicBacking.Network = vNic.MoRef;
                  nicBacking.DeviceName = networkName;
                  nic.AddressType = "generated";
                  nic.Backing = nicBacking;
                  nic.Key = 4;
                  nicSpec.Device = nic;
               }

               VirtualDeviceConfigSpec[] specs = { nicSpec };
               VirtualMachineConfigSpec vmConfSpec = new VirtualMachineConfigSpec();
               vmConfSpec.DeviceChange = specs;

               vm.ReconfigVM_Task(vmConfSpec);
            }
         }
         catch (VimException e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         } catch (Exception e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
      }
      public void RemoveNetworkAdapterFromVM(string vmName, string networkName) {
         try {
            VirtualMachine vm = this.GetVirtualMachines().Where(_vm => _vm.Name == vmName).FirstOrDefault();
            if (vm != null) {
               VirtualMachineConfigSpec vmConfigSpec = new VirtualMachineConfigSpec();
               VirtualDeviceConfigSpec nicSpec = new VirtualDeviceConfigSpec();
               VirtualEthernetCard nic = null;
               VirtualDevice[] nics = vm.Config.Hardware.Device.Where(device => device is VMware.Vim.VirtualEthernetCard).Select(vnic => vnic as VirtualEthernetCard).ToArray();
               nicSpec.Operation = VirtualDeviceConfigSpecOperation.remove;
               nic = (VirtualEthernetCard)nics.Where(vnic => vnic.DeviceInfo.Summary.Equals(networkName)).FirstOrDefault();               
               if (nic != null) {
                  nicSpec.Device = nic;
               }
               VirtualDeviceConfigSpec[] nicSpecArray = { nicSpec };
               vmConfigSpec.DeviceChange = nicSpecArray;
               vm.ReconfigVM_Task(vmConfigSpec);
            }
         } catch(VimException e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
      }
      public void ChangeVMNetworkAdapterPortGroup(string vmName, string oldNetworkName, string newNetworkName) {
         try {
            VirtualMachine vm = this.GetVirtualMachines().Where(_vm => _vm.Name == vmName).FirstOrDefault();
            if (vm != null) {
               VirtualMachineConfigSpec vmConfigSpec = new VirtualMachineConfigSpec();
               VirtualDeviceConfigSpec nicSpec = new VirtualDeviceConfigSpec();
               VirtualEthernetCard nic = null;
               VirtualDevice[] nics = vm.Config.Hardware.Device.Where(device => device is VMware.Vim.VirtualEthernetCard).Select(vnic => vnic as VirtualEthernetCard).ToArray();
               nicSpec.Operation = VirtualDeviceConfigSpecOperation.edit;
               nic = (VirtualEthernetCard)nics.Where(vnic => vnic.DeviceInfo.Summary.Equals(oldNetworkName)).FirstOrDefault();
               
               VirtualEthernetCardNetworkBackingInfo nicBacking = new VirtualEthernetCardNetworkBackingInfo();
               Network vNic = new Network(vSphereClient, vm.Runtime.Host);
               nicBacking.Network = vNic.MoRef;
               nicBacking.DeviceName = newNetworkName;

               if (nic != null) {
                  nic.Backing = nicBacking;
                  nicSpec.Device = nic;
               }
               VirtualDeviceConfigSpec[] nicSpecArray = { nicSpec };
               vmConfigSpec.DeviceChange = nicSpecArray;
               vm.ReconfigVM_Task(vmConfigSpec);
            }
         }
         catch (VimException e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
      }
      /// <summary>
      /// Gets all port group names that a virtual machine is connected to
      /// </summary>
      /// <param name="vmName">The name of the virtual machine to filter on</param>
      /// <returns></returns>
      public List<String> GetVMNetworkAdapterPortGroups(string vmName) {
         List<String> VMNetworkAdapterPortGroups = new List<String>();
         try {
            VirtualMachine vm = this.GetVirtualMachines().Where(_vm => _vm.Name == vmName).FirstOrDefault();
            if (vm != null) {               
               foreach(VirtualEthernetCard vnic in vm.Config.Hardware.Device.Where(device => device is VMware.Vim.VirtualEthernetCard).Select(vnic => vnic as VirtualEthernetCard).ToArray()) {
                  VMNetworkAdapterPortGroups.Add(vnic.DeviceInfo.Summary);
               }               
            }
         }
         catch (VimException e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
         return VMNetworkAdapterPortGroups;
      }
      /// <summary>
      /// Gets all port group names that a virtual machine is connected to
      /// </summary>
      /// <param name="vmName">The name of the virtual machine to filter on</param>
      /// <returns></returns>
      public List<String> GetHostStandardPortGroups(VMware.Vim.HostSystem host) {
         List<String> HostPortGroups = new List<String>();
         try {
            if (host != null) {
               foreach(ManagedObjectReference mobj in host.Network) {
                  Network network = (Network)vSphereClient.GetView(mobj, null);
                  HostPortGroups.Add(network.Name);
               }                                       
            }
         }
         catch (VimException e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
         catch (Exception e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }         
         return HostPortGroups;
      }
      public List<String> GetHostVirtualSwitches(VMware.Vim.HostSystem host) {
         List<String> HostVirtualSwitches = new List<String>();         
         try {
            if (host != null) {
               ManagedObjectReference mobj = host.ConfigManager.NetworkSystem;
               HostNetworkSystem networkSystem = (HostNetworkSystem)vSphereClient.GetView(mobj, null);
               foreach (HostVirtualSwitch hvsw in networkSystem.NetworkInfo.Vswitch) {
                  HostVirtualSwitches.Add(hvsw.Name);
               }
            }
         }
         catch (VimException e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
         catch (Exception e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
         return HostVirtualSwitches;
      }
      /// <summary>
      /// Get all virtual switches of a host that match a filter 
      /// </summary>
      /// <param name="host">HostSystem instance object</param>
      /// <param name="nameFilter">The filter</param>
      /// <returns></returns>
      public List<HostVirtualSwitch> GetHostVirtualSwitches(VMware.Vim.HostSystem host, string nameFilter) {
         List<HostVirtualSwitch> HostVirtualSwitches = new List<HostVirtualSwitch>();
         try {
            if (host != null) {
               ManagedObjectReference mobj = host.ConfigManager.NetworkSystem;
               HostNetworkSystem networkSystem = (HostNetworkSystem)vSphereClient.GetView(mobj, null);
               foreach (HostVirtualSwitch hvsw in networkSystem.NetworkInfo.Vswitch.Where(sw => sw.Portgroup.Where(swp => swp.Contains(nameFilter)).Count() > 0)) {
                  HostVirtualSwitches.Add(hvsw);
               }
            }
         }
         catch (VimException e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
         catch (Exception e) {
            lock (m_lock) {
               WriteLogText(logWriter, e.Message.ToString());
            }
         }
         return HostVirtualSwitches;
      }
   }
   public class VmrcLogonInfo {
      public string VmkID { get; set; }
      public VMware.Vim.SessionManagerLocalTicket LocalTicket { get; set; }
      public string CloneTicket { get; set; }
      public int ConsoleConnections { get; set; }
   }
   public class VirtualMachineWrapper {
      public int NumMksConnections { get; set; }
      public bool PowerState { get; set; }
      public string IpAddress { get; set; }
      public string HostName { get; set; }
      /// <summary>
      /// Possible values are:
      /// guestToolsExecutingScripts - VMware Tools is starting. 
      /// guestToolsNotRunning - VMware Tools is not running.
      /// guestToolsRunning - VMware Tools is running.
      /// </summary>
      public string ToolsRunningStatus { get; set; }
      public string ToolsVersionStatus { get; set; }
      public int? NumCpu { get; set; }
      public int? MemorySizeMB { get; set; }
      public int? NumVirtualDisks { get; set; }
      public string Name { get; set; }
      public GuestDiskInfoWrapper[] Disk { get; set; }
   }
   public class GuestDiskInfoWrapper {
      /// <summary>
      /// Capacity of disk in bytes
      /// </summary>
      public long? Capacity { get; set; }
      /// <summary>
      /// This is the drive letter on the Windows systems
      /// </summary>
      public string DiskPath { get; set; }
      /// <summary>
      /// Amount of free space in bytes
      /// </summary>
      public long? FreeSpace { get; set; }

      static public explicit operator GuestDiskInfoWrapper(VMware.Vim.GuestDiskInfo disk) {
         return new GuestDiskInfoWrapper() { Capacity = disk.Capacity, DiskPath = disk.DiskPath, FreeSpace = disk.FreeSpace };
      }
   }
}

