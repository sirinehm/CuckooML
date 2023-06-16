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

import collections

import logging
import os

from cuckoo.common.abstracts import Processing, BehaviorHandler
from cuckoo.common.config import config


from .platform.windows import WindowsMonitor

warnings.filterwarnings("ignore")

log = logging.getLogger(__name__)




def train_model():

    dataset_path = "/home/cuckoo/.virtualenvs/cuckoo-tes/lib/python2.7/site-packages/cuckoo/processing/datasets/dynamic.csv"

    priority_calls = ['InternetOpen', 'GetProcAddress', 'CreateToolhelp32Snapshot', 'HttpOpenRequest', 'ioctlsocket', 'OpenProcess', 'CreateThread', 'SetWindowsHookExA', 'InternetReadFile', 'FindResource', 'CountClipboardFormats', 'WriteProcessMemory', 'free', 'GetEIP', 'GetAsyncKeyState', 'DispatchMessage', 'SizeOfResource', 'GetFileSize', 'GetTempPathA', 'NtUnmapViewOfSection', 'WSAIoctl', 'ReadFile', 'GetTickCount', 'Fopen', 'malloc', 'InternetConnect', 'Sscanf', 'GetKeyState', 'GetModuleHandle', 'ReadProcessMemory', 'LockResource', 'RegSetValueEx', 'ShellExecute', 'IsDebuggerPresent', 'WSASocket', 'VirtualProtect', 'bind', 'WinExec', 'GetForeGroundWindow', 'CreateProcessA', 'LoadLibraryA', 'socket', 'LoadResource', 'CreateFileA', 'VirtualAllocEx', 'HTTPSendRequest', 'BroadcastSystemMessage', 'FindWindowsA', 'Process32First', 'CreateRemoteThread', 'GetWindowsThreadProcessId', 'URLDownloadToFile', 'SetWindowsHookEx', 'GetMessage']

    interesting_calls = ['VirtualAlloc', 'MoveFileA', 'FindResourceA', 'GetWindowsDirectoryA', 'PeekMessageA', 'FindClose', 'MapVirtualKeyA', 'SetEnvironmentVariableA', 'GetKeyboardState', 'mciSendStringA', 'GetFileType', 'RasEnumConnectionsA', 'FlushFileBuffers', 'GetVersionExA', 'ioctlsocket', 'WSAAsyncSelect', 'GetCurrentThreadId', 'LookupPrivilegeValueA', 'GetCurrentProcess', 'SetStdHandle', 'WSACleanup', 'WSAStartup', 'CreateMutexA', 'GetForegroundWindow', 'SetKeyboardState', 'OleInitialize', 'SetUnhandledExceptionFilter', 'UnhookWindowsHookEx', 'GetModuleHandleA', 'GetSystemDirectoryA', 'RegOpenKey', 'GetFileAttributesA', 'AdjustTokenPrivileges', 'FreeLibrary', 'GetStartupInfoA', 'RasGetConnectStatusA', 'OpenProcessToken', 'PostMessageA', 'GetTickCount', 'GetExitCodeProcess', 'SetFileTime', 'DispatchMessageA', 'RegDeleteValueA', 'FreeEnvironmentStringsA', 'CallNextHookEx', 'GetUserNameA', 'HeapCreate', 'GlobalMemoryStatus', 'SetFileAttributesA', 'URLDownloadToFileA', 'RaiseException', 'WSAGetLastError', 'RegCreateKeyExA', 'keybd_event', 'ExitWindowsEx', 'GetCommandLineA', 'RegCreateKeyA', 'FreeEnvironmentStringsW', 'UnhandledExceptionFilter', 'GetExitCodeThread', 'PeekNamedPipe']

    calls = priority_calls + interesting_calls

    # we convert each function call to lowercase letters.
    features = [call.lower() for call in calls]

    dataset_path = "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/datasets/dynamic.csv"

    df = pd.read_csv(dataset_path, index_col='id')
    #a9ra les lignes lkol w les colonne men colonne thenya
    X = df.values[:,1:]
    #a9ra les lignes lkol w  colonne loula khw
    y = df.values[:,0]

    le = LabelEncoder()

    y_df = pd.DataFrame(y, dtype=str)

    y = y_df.apply(le.fit_transform).values[:,:]

    encoded_labels = dict(zip(le.classes_, le.transform(le.classes_))) # encoded_labels = { trojan:0,ransomware:1}

    target_names = list(encoded_labels.keys()) # ["trojan" ,"ransomware"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.4, random_state=42, stratify=y)


    xgb_clf = XGBClassifier()
    xgb_clf.fit(X_train, y_train)



    
    return (xgb_clf, target_names, features)


if not os.path.exists("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/dynamic.joblib"):
    model, target_names, features = train_model()
    joblib.dump(model, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/dynamic.joblib")
    joblib.dump(target_names, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/labels/dynamic.joblib")
    joblib.dump(features, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/features/dynamic.joblib")

else:
    target_names = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/labels/dynamic.joblib")
    model = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/dynamic.joblib")
    features = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/features/dynamic.joblib")  






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
    key = "dynamicML"

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

        class_ = 'Unknown'


        try:
            api_keys=[]
            for process, api_calls in behavior2["apistats"].items():
                for api_call in api_calls.keys():
                    api_keys.append(api_call)
        except:
            api_keys = []


        apis = [class_] + api_keys
        
            
        data_df = pd.DataFrame(np.array(apis).reshape(1, -1))
            
        df = pd.DataFrame(0, index=np.arange(len(data_df)), columns=["class"] + features)

        for i in range(len(data_df.values)):
            df.iloc[i, 0] = data_df.values[i][0]
            for value in data_df.values[i][1:]:
                if type(value) != str:
                    continue
                value = value.lower()
                if not value in features:
                    continue
                df.loc[i, value] = 1
                
        X_sample = df.values[:,1:]
        y = df.values[:,0]

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
        dynamicML = {
            "proba": proba,
            "family": family,
            "confidence": confidence,
            "api_keys": api_keys
        }
                      
        return dynamicML
