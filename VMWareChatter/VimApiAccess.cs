using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security;
using System.IO;
using System.Reflection;
using System.Web.Services.Protocols;
using System.Web.Services;
using Microsoft.Web.Services3;
//using Vim25Api;
using VimApi_55;

namespace VMWareChatter {
   /*  
    *  Requires namespace VMware.Vim and VimApi_55
    *  Requires Vim25Service.dll
    */
   internal class VimApiAccess : IDisposable {
      VimService vimService = null;
      VMware.Vim.ServiceContent vConnection = null;

      public void Dispose() {
         this.Disconnect();
      }
      public void AddVirtualNic(VMware.Vim.HostConfigManager configMgr, string portGroupName, string IPaddress, string subNetmask) {
         VMware.Vim.ManagedObjectReference nwSystem = configMgr.NetworkSystem;

         HostVirtualNicSpec vNicSpec = new HostVirtualNicSpec();
         HostIpConfig ipConfig = new HostIpConfig();
         
         ipConfig.dhcp = false;
         ipConfig.ipAddress = IPaddress;
         ipConfig.subnetMask = subNetmask;
         vNicSpec.ip = ipConfig;
                  
         vimService.AddVirtualNic(nwSystem != null ? new VimApi_55.ManagedObjectReference() {
            type = nwSystem.Type,
            Value = nwSystem.Value
         } : null, portGroupName, vNicSpec);
      }
      public void RemovePortGroup(VMware.Vim.HostConfigManager configMgr, string portGroupName) {
         VMware.Vim.ManagedObjectReference nMob = configMgr.NetworkSystem;
         //HostNetworkInfo nwSystem = (HostNetworkInfo)this.GetDynamicProperty(nMob, "networkInfo");
         vimService.RemovePortGroup(nMob != null ? new VimApi_55.ManagedObjectReference() {
            type = nMob.Type,
            Value = nMob.Value
         } : null, portGroupName);
      }
      public void CreatePortGroup(VMware.Vim.HostConfigManager configMgr, string portGroupName, string vSwitchName) {
         VMware.Vim.ManagedObjectReference nMob = configMgr.NetworkSystem;

         HostPortGroupSpec portgrp = new HostPortGroupSpec();
         portgrp.name = portGroupName;
         portgrp.vswitchName = vSwitchName;
         portgrp.policy = new HostNetworkPolicy();

         vimService.AddPortGroup(nMob != null ? new VimApi_55.ManagedObjectReference() {
            type = nMob.Type,
            Value = nMob.Value
         } : null, portgrp);
      }

      public VimApiAccess(VMware.Vim.ServiceContent connection) {
         this.vConnection = connection;
      }
      private Object GetDynamicProperty(VMware.Vim.ManagedObjectReference mor, String propertyName) {
         VimApi_55.ObjectContent[] objContent = GetObjectProperties(null, mor,
               new String[] { propertyName });

         Object propertyValue = null;
         if (objContent != null) {
            VimApi_55.DynamicProperty[] dynamicProperty = objContent[0].propSet;
            if (dynamicProperty != null) {
               Object dynamicPropertyVal = dynamicProperty[0].val;
               String dynamicPropertyName = dynamicPropertyVal.GetType().FullName;
               propertyValue = dynamicPropertyVal;

            }
         }
         return propertyValue;
      }
      private VimApi_55.ObjectContent[] GetObjectProperties(
           VMware.Vim.ManagedObjectReference collector,
           VMware.Vim.ManagedObjectReference mobj, string[] properties
        ) {
         if (mobj == null) {
            return null;
         }

         VimApi_55.ManagedObjectReference usecoll = collector != null ? new VimApi_55.ManagedObjectReference() {
            type = collector.Type,
            Value = collector.Value
         } : null;
         if (usecoll == null) {
            usecoll = new VimApi_55.ManagedObjectReference() {
               type = this.vConnection.PropertyCollector.Type,
               Value = this.vConnection.PropertyCollector.Value
            };
         }

         VimApi_55.PropertyFilterSpec spec = new VimApi_55.PropertyFilterSpec();
         spec.propSet = new VimApi_55.PropertySpec[] { new VimApi_55.PropertySpec() };
         spec.propSet[0].all = properties == null || properties.Length == 0;
         spec.propSet[0].allSpecified = spec.propSet[0].all;
         spec.propSet[0].type = mobj.Type;
         spec.propSet[0].pathSet = properties;

         spec.objectSet = new VimApi_55.ObjectSpec[] { new VimApi_55.ObjectSpec() };
         spec.objectSet[0].obj = mobj != null ? new VimApi_55.ManagedObjectReference() {
            type = mobj.Type,
            Value = mobj.Value
         } : null;
         spec.objectSet[0].skip = false;
         return RetrievePropertiesEx(usecoll, new VimApi_55.PropertyFilterSpec[] { spec });
      }
      private VimApi_55.ObjectContent[] RetrievePropertiesEx(VimApi_55.ManagedObjectReference propertyCollector, VimApi_55.PropertyFilterSpec[] specs) {
         return RetrievePropertiesEx(propertyCollector, specs, null);
      }

      private VimApi_55.ObjectContent[] RetrievePropertiesEx(VimApi_55.ManagedObjectReference propertyCollector, VimApi_55.PropertyFilterSpec[] specs, int? maxObjects) {
         List<VimApi_55.ObjectContent> objectList = new List<VimApi_55.ObjectContent>();
         //VimService _service = new VimService();
         var result =
                  vimService.RetrievePropertiesEx(propertyCollector, specs, new VimApi_55.RetrieveOptions() {
                     maxObjects = maxObjects.GetValueOrDefault(),
                     maxObjectsSpecified = (maxObjects != null)
                  });
         if (result != null) {
            string token = result.token;
            objectList.AddRange(result.objects.AsEnumerable());
            while (token != null && !string.Empty.Equals(token)) {
               result = vimService.ContinueRetrievePropertiesEx(propertyCollector, token);
               if (result != null) {
                  token = result.token;
                  objectList.AddRange(result.objects.AsEnumerable());
               }
            }
         }
         return objectList.ToArray();
      }
      /// <summary>
      /// Creates an instance of the VMA proxy and establishes a connection
      /// </summary>
      /// <param name="url"></param>
      /// <param name="username"></param>
      /// <param name="password"></param>
      public void Connect(string url, string username, string password) {
         if (vimService != null) {
            if (vConnection != null)
               vimService.Logout(new VimApi_55.ManagedObjectReference() {
                  type = vConnection.SessionManager.Type,
                  Value = vConnection.SessionManager.Value
               });

            vimService.Dispose();
            vimService = null;
            vConnection = null;
         }

         vimService = new VimService();
         vimService.Url = url;
         vimService.Timeout = 600000; //The value can be set to some higher value also.
         vimService.CookieContainer = new System.Net.CookieContainer();


         if (vConnection.SessionManager != null) {
            vimService.Login(new VimApi_55.ManagedObjectReference() {
               type = vConnection.SessionManager.Type,
               Value = vConnection.SessionManager.Value
            }, username, password, null);
         }
      }
      public void Disconnect() {
         if (vimService != null) {
            vimService.Dispose();
            vimService = null;            
         }
      }
   }
}
