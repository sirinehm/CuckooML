import collections
import logging
import os
import joblib
import os

import pandas as pd
import numpy as np
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder 
from sklearn.model_selection import train_test_split
import os
import joblib
import warnings
import joblib
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder 
from sklearn.model_selection import train_test_split
import streamlit as st
import os
import joblib
import warnings
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from xgboost import XGBClassifier
import numpy as np
import collections

import logging
import os

from cuckoo.common.abstracts import Processing, BehaviorHandler
from cuckoo.common.config import config


from .platform.windows import WindowsMonitor

warnings.filterwarnings("ignore")

log = logging.getLogger(__name__)




def train_model():

    df = pd.read_csv(r"/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/datasets/apicallsclass.csv")
    df.dropna(subset=['class'], inplace=True)
    df.loc[df['class'] == 0, 'class'] = "benign"
    df.loc[df['class'] == 1, 'class'] = "malware"
    features = df.columns[1:-1]
    X = df[features].values
    y = df.iloc[:, -1].values
    le = LabelEncoder()
    y_df = pd.DataFrame(y, dtype=str)
    y_df.apply(le.fit_transform)
    y = y_df.apply(le.fit_transform).values[:, :]
    encoded_labels = dict(zip(le.classes_, le.transform(le.classes_))) 
    target_names = list(encoded_labels.keys()) 
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.4, random_state=42, stratify=y)
    y_train = y_train.ravel()
    data = X_train
    scaler = MinMaxScaler()
    scaler.fit(data)
    scaler.transform(data)
    X_train = scaler.transform(data)
    X_test = scaler.transform(X_test)

    xgb_clf = XGBClassifier(learning_rate = 0.2, 
                            max_depth = 6, 
                            min_child_weight = 1,
                        subsample = 1)
    xgb_clf.fit(X_train, y_train)
    return (xgb_clf, target_names, features,scaler)

model, target_names, features, scaler = train_model()
if not os.path.exists("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/apis_seq.joblib"):
    model, target_names, features, scaler = train_model()
    joblib.dump(model, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/apis_seq.joblib")
    joblib.dump(target_names, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/labels/api_seq.joblib")
    joblib.dump(features, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/features/api_seq.joblib")
    joblib.dump(scaler, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/api_scaler.joblib")
else:
    target_names = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/labels/api_seq.joblib")
    model = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/apis_seq.joblib")
    features = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/features/api_seq.joblib")    
    scaler = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/api_scaler.joblib")


API_Calls= ['NtOpenThread', 'ExitWindowsEx', 'FindResourceW', 'CryptExportKey', 'CreateRemoteThreadEx', 'MessageBoxTimeoutW', 'InternetCrackUrlW', 'StartServiceW', 'GetFileSize', 'GetVolumeNameForVolumeMountPointW', 'GetFileInformationByHandle', 'CryptAcquireContextW', 'RtlDecompressBuffer', 'SetWindowsHookExA', 'RegSetValueExW', 'LookupAccountSidW', 'SetUnhandledExceptionFilter', 'InternetConnectA', 'GetComputerNameW', 'RegEnumValueA', 'NtOpenFile', 'NtSaveKeyEx', 'HttpOpenRequestA', 'recv', 'GetFileSizeEx', 'LoadStringW', 'SetInformationJobObject', 'WSAConnect', 'CryptDecrypt', 'GetTimeZoneInformation', 'InternetOpenW', 'CoInitializeEx', 'CryptGenKey', 'GetAsyncKeyState', 'NtQueryInformationFile', 'GetSystemMetrics', 'NtDeleteValueKey', 'NtOpenKeyEx', 'sendto', 'IsDebuggerPresent', 'RegQueryInfoKeyW', 'NetShareEnum', 'InternetOpenUrlW', 'WSASocketA', 'CopyFileExW', 'connect', 'ShellExecuteExW', 'SearchPathW', 'GetUserNameA', 'InternetOpenUrlA', 'LdrUnloadDll', 'EnumServicesStatusW', 'EnumServicesStatusA', 'WSASend', 'CopyFileW', 'NtDeleteFile', 'CreateActCtxW', 'timeGetTime', 'MessageBoxTimeoutA', 'CreateServiceA', 'FindResourceExW', 'WSAAccept', 'InternetConnectW', 'HttpSendRequestA', 'GetVolumePathNameW', 'RegCloseKey', 'InternetGetConnectedStateExW', 'GetAdaptersInfo', 'shutdown', 'NtQueryMultipleValueKey', 'NtQueryKey', 'GetSystemWindowsDirectoryW', 'GlobalMemoryStatusEx', 'GetFileAttributesExW', 'OpenServiceW', 'getsockname', 'LoadStringA', 'UnhookWindowsHookEx', 'NtCreateUserProcess', 'Process32NextW', 'CreateThread', 'LoadResource', 'GetSystemTimeAsFileTime', 'SetStdHandle', 'CoCreateInstanceEx', 'GetSystemDirectoryA', 'NtCreateMutant', 'RegCreateKeyExW', 'IWbemServices_ExecQuery', 'NtDuplicateObject', 'Thread32First', 'OpenSCManagerW', 'CreateServiceW', 'GetFileType', 'MoveFileWithProgressW', 'NtDeviceIoControlFile', 'GetFileInformationByHandleEx', 'CopyFileA', 'NtLoadKey', 'GetNativeSystemInfo', 'NtOpenProcess', 'CryptUnprotectMemory', 'InternetWriteFile', 'ReadProcessMemory', 'gethostbyname', 'WSASendTo', 'NtOpenSection', 'listen', 'WSAStartup', 'socket', 'OleInitialize', 'FindResourceA', 'RegOpenKeyExA', 'RegEnumKeyExA', 'NtQueryDirectoryFile', 'CertOpenSystemStoreW', 'ControlService', 'LdrGetProcedureAddress', 'GlobalMemoryStatus', 'NtSetInformationFile', 'OutputDebugStringA', 'GetAdaptersAddresses', 'CoInitializeSecurity', 'RegQueryValueExA', 'NtQueryFullAttributesFile', 'DeviceIoControl', '__anomaly__', 'DeleteFileW', 'GetShortPathNameW', 'NtGetContextThread', 'GetKeyboardState', 'RemoveDirectoryA', 'InternetSetStatusCallback', 'NtResumeThread', 'SetFileInformationByHandle', 'NtCreateSection', 'NtQueueApcThread', 'accept', 'DecryptMessage', 'GetUserNameExW', 'SizeofResource', 'RegQueryValueExW', 'SetWindowsHookExW', 'HttpOpenRequestW', 'CreateDirectoryW', 'InternetOpenA', 'GetFileVersionInfoExW', 'FindWindowA', 'closesocket', 'RtlAddVectoredExceptionHandler', 'IWbemServices_ExecMethod', 'GetDiskFreeSpaceExW', 'TaskDialog', 'WriteConsoleW', 'CryptEncrypt', 'WSARecvFrom', 'NtOpenMutant', 'CoGetClassObject', 'NtQueryValueKey', 'NtDelayExecution', 'select', 'HttpQueryInfoA', 'GetVolumePathNamesForVolumeNameW', 'RegDeleteValueW', 'InternetCrackUrlA', 'OpenServiceA', 'InternetSetOptionA', 'CreateDirectoryExW', 'bind', 'NtShutdownSystem', 'DeleteUrlCacheEntryA', 'NtMapViewOfSection', 'LdrGetDllHandle', 'NtCreateKey', 'GetKeyState', 'CreateRemoteThread', 'NtEnumerateValueKey', 'SetFileAttributesW', 'NtUnmapViewOfSection', 'RegDeleteValueA', 'CreateJobObjectW', 'send', 'NtDeleteKey', 'SetEndOfFile', 'GetUserNameExA', 'GetComputerNameA', 'URLDownloadToFileW', 'NtFreeVirtualMemory', 'recvfrom', 'NtUnloadDriver', 'NtTerminateThread', 'CryptUnprotectData', 'NtCreateThreadEx', 'DeleteService', 'GetFileAttributesW', 'GetFileVersionInfoSizeExW', 'OpenSCManagerA', 'WriteProcessMemory', 'GetSystemInfo', 'SetFilePointer', 'Module32FirstW', 'ioctlsocket', 'RegEnumKeyW', 'RtlCompressBuffer', 'SendNotifyMessageW', 'GetAddrInfoW', 'CryptProtectData', 'Thread32Next', 'NtAllocateVirtualMemory', 'RegEnumKeyExW', 'RegSetValueExA', 'DrawTextExA', 'CreateToolhelp32Snapshot', 'FindWindowW', 'CoUninitialize', 'NtClose', 'WSARecv', 'CertOpenStore', 'InternetGetConnectedState', 'RtlAddVectoredContinueHandler', 'RegDeleteKeyW', 'SHGetSpecialFolderLocation', 'CreateProcessInternalW', 'NtCreateDirectoryObject', 'EnumWindows', 'DrawTextExW', 'RegEnumValueW', 'SendNotifyMessageA', 'NtProtectVirtualMemory', 'NetUserGetLocalGroups', 'GetUserNameW', 'WSASocketW', 'getaddrinfo', 'AssignProcessToJobObject', 'SetFileTime', 'WriteConsoleA', 'CryptDecodeObjectEx', 'EncryptMessage', 'system', 'NtSetContextThread', 'LdrLoadDll', 'InternetGetConnectedStateExA', 'RtlCreateUserThread', 'GetCursorPos', 'Module32NextW', 'RegCreateKeyExA', 'NtLoadDriver', 'NetUserGetInfo', 'SHGetFolderPathW', 'GetBestInterfaceEx', 'CertControlStore', 'StartServiceA', 'NtWriteFile', 'Process32FirstW', 'NtReadVirtualMemory', 'GetDiskFreeSpaceW', 'GetFileVersionInfoW', 'FindFirstFileExW', 'FindWindowExW', 'GetSystemWindowsDirectoryA', 'RegOpenKeyExW', 'CoCreateInstance', 'NtQuerySystemInformation', 'LookupPrivilegeValueW', 'NtReadFile', 'ReadCabinetState', 'GetForegroundWindow', 'InternetCloseHandle', 'FindWindowExA', 'ObtainUserAgentString', 'CryptCreateHash', 'GetTempPathW', 'CryptProtectMemory', 'NetGetJoinInformation', 'NtOpenKey', 'GetSystemDirectoryW', 'DnsQuery_A', 'RegQueryInfoKeyA', 'NtEnumerateKey', 'RegisterHotKey', 'RemoveDirectoryW', 'FindFirstFileExA', 'CertOpenSystemStoreA', 'NtTerminateProcess', 'NtSetValueKey', 'CryptAcquireContextA', 'SetErrorMode', 'UuidCreate', 'RtlRemoveVectoredExceptionHandler', 'RegDeleteKeyA', 'setsockopt', 'FindResourceExA', 'NtSuspendThread', 'GetFileVersionInfoSizeW', 'NtOpenDirectoryObject', 'InternetQueryOptionA', 'InternetReadFile', 'NtCreateFile', 'NtQueryAttributesFile', 'HttpSendRequestW', 'CryptHashMessage', 'CryptHashData', 'NtWriteVirtualMemory', 'SetFilePointerEx', 'CertCreateCertificateContext', 'DeleteUrlCacheEntryW', '__exception__']




class ApiStats(BehaviorHandler):
    """Counts API calls."""
    key = "apistats"
    event_types = ["apicall"]

    def __init__(self, *args, **kwargs):
        super(ApiStats, self).__init__(*args, **kwargs)
        self.processes = collections.defaultdict(lambda: collections.defaultdict(lambda: 0))

    def handle_event(self, event):
        self.processes["%d" % event["pid"]][event["api"]] += 1

    def run(self):
        return self.processes

class Static(Processing):
    key = "api_call_seqML"

    def _enum_logs(self):
        """Enumerate all behavior logs."""
        if not os.path.exists(self.logs_path):
            log.warning("Analysis results folder does not exist at path %r.", self.logs_path)
            return

        logs = os.listdir(self.logs_path)
        if not logs:
            log.warning("Analysis results folder does not contain any behavior log files.")
            return

        for fname in logs:
            path = os.path.join(self.logs_path, fname)
            if not os.path.isfile(path):
                log.warning("Behavior log file %r is not a file.", fname)
                continue

            limit = config("cuckoo:processing:analysis_size_limit")
            if limit and os.stat(path).st_size > limit:
                # This needs to be a big alert.
                log.critical("Behavior log file %r is too big, skipped.", fname)
                continue

            yield path

    def run(self):
        """Run analysis.
        @return: results dict.
        """
        self.state = {}

        # these handlers will be present for any analysis, regardless of platform/format
        handlers = [
            ApiStats(self),
            # platform specific stuff
            WindowsMonitor(self, task_id=self.task["id"]),
        ]

        # doesn't really work if there's no task, let's rely on the file name for now
        # # certain handlers only makes sense for a specific platform
        # # this allows us to use the same filenames/formats without confusion
        # if self.task.machine.platform == "windows":
        #     handlers += [
        #         WindowsMonitor(self),
        #     ]
        # elif self.task.machine.platform == "linux":
        #     handlers += [
        #         LinuxSystemTap(self),
        #     ]

        # create a lookup map
        interest_map = {}
        for h in handlers:
            for event_type in h.event_types:
                if event_type not in interest_map:
                    interest_map[event_type] = []

                # If available go for the specific event type handler rather
                # than the generic handle_event.
                if hasattr(h, "handle_%s_event" % event_type):
                    fn = getattr(h, "handle_%s_event" % event_type)
                    interest_map[event_type].append(fn)
                elif h.handle_event not in interest_map[event_type]:
                    interest_map[event_type].append(h.handle_event)

        # Each log file should be parsed by one of the handlers. This handler
        # then yields every event in it which are forwarded to the various
        # behavior/analysis/etc handlers.
        for path in self._enum_logs():
            for handler in handlers:
                # ... whether it is responsible
                if not handler.handles_path(path):
                    continue

                # ... and then let it parse the file
                for event in handler.parse(path):
                    # pass down the parsed message to interested handlers
                    for hhandler in interest_map.get(event["type"], []):
                        res = hhandler(event)
                        # We support one layer of "generating" new events,
                        # which we'll pass on again (in case the handler
                        # returns some).
                        if not res:
                            continue

                        for subevent in res:
                            for hhandler2 in interest_map.get(subevent["type"], []):
                                hhandler2(subevent)

        behavior2 = {}

        for handler in handlers:
            try:
                r = handler.run()
                if not r:
                    continue

                behavior2[handler.key] = r
            except:
                log.exception("Failed to run partial behavior class \"%s\"", handler.key)

                apiss = []
        
        
        api_seq=[]
        processes = behavior2["processes"]
        for process in processes:
            for call in process["calls"]:
                # Access individual call properties here
                api_seq.append(call["api"])  


        indices = []
        for call in api_seq:
            if call in API_Calls:
                index = API_Calls.index(call)
                indices.append(index)
        features = ['t_0', 't_1', 't_2', 't_3', 't_4', 't_5', 't_6', 't_7', 't_8', 't_9', 't_10', 't_11', 't_12', 't_13', 't_14', 't_15', 't_16', 't_17', 't_18', 't_19', 't_20', 't_21', 't_22', 't_23', 't_24', 't_25', 't_26', 't_27', 't_28', 't_29', 't_30', 't_31', 't_32', 't_33', 't_34', 't_35', 't_36', 't_37', 't_38', 't_39', 't_40', 't_41', 't_42', 't_43', 't_44', 't_45', 't_46', 't_47', 't_48', 't_49', 't_50', 't_51', 't_52', 't_53', 't_54', 't_55', 't_56', 't_57', 't_58', 't_59', 't_60', 't_61', 't_62', 't_63', 't_64', 't_65', 't_66', 't_67', 't_68', 't_69', 't_70', 't_71', 't_72', 't_73', 't_74', 't_75', 't_76', 't_77', 't_78', 't_79', 't_80', 't_81', 't_82', 't_83', 't_84', 't_85', 't_86', 't_87', 't_88', 't_89', 't_90', 't_91', 't_92', 't_93', 't_94', 't_95', 't_96', 't_97', 't_98', 't_99']

        df_length = 1
        df = pd.DataFrame(index=np.arange(df_length), columns=features + ["class"])
        df.fillna(-1, inplace=True)

        i=0
        for column_index in df.columns:
            if i< len (indices) and i < df.size :
                df[column_index] = indices[i]
                i=i+1
            else :
                break
        
        
        X_sample = df[features].values
        y = df.iloc[:, -1].values

        X_sample=scaler.transform(X_sample)

        predicted_list = model.predict_proba(X_sample)
        result = model.predict(X_sample)[0]
        confidence = round(predicted_list[0][result]*100, 2)



        if result == 0:
            family = target_names[result]
        else:
            family = target_names[result]

        proba= []

        for p,n in zip(predicted_list[0], target_names):
            proba.append("{} : {}".format(n, round(p, 2)))

        # Add the dynamicML section to the report
        apis_seq = {
            "proba": proba,
            "family": family,
            "confidence": confidence
        }
                      
        return apis_seq
