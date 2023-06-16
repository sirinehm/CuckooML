
from cuckoo.common.abstracts import Processing
from cuckoo.common.objects import File
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from datetime import datetime
import pandas as pd

import streamlit as st
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
import yara
import lief
import yaml
import hashlib
import pefile
import os
import joblib
import warnings
import logging

warnings.filterwarnings("ignore")
log = logging.getLogger(__name__)

def load_config(file_path):
    with open(file_path, "r") as f:
        return yaml.safe_load(f) #The yaml.safe_load function takes a YAML-formatted string as input, and converts it into a Python object
                                 #that represents the data contained in the string

# The second part of the code loads a configuration file named "config.yaml" using the load_config function, and assigns the resulting 
# data structure to the variable config. It then extracts a dictionary of static configuration settings from this data structure by 
# accessing the value associated with the key 'STATIC', and assigns this dictionary to the variable static_config.

config = load_config("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/config.yaml")
static_config = config['STATIC'] # ==> type of static_config is a dictionary 

yara_rules_path = static_config['YARA_RULES_PATH']

all_capabilities = ['inject_thread', 'create_process', 'persistence', 'hijack_network', 'create_service', 'create_com_service', 'network_udp_sock', 'network_tcp_listen', 'network_dyndns', 'network_toredo', 'network_smtp_dotNet', 'network_smtp_raw', 'network_smtp_vb', 'network_p2p_win', 'network_tor', 'network_irc', 'network_http', 'network_dropper', 'network_ftp', 'network_tcp_socket', 'network_dns', 'network_ssl', 'network_dga', 'bitcoin', 'certificate', 'escalate_priv',
                    'screenshot', 'lookupip', 'dyndns', 'lookupgeo', 'keylogger', 'cred_local', 'sniff_audio', 'cred_ff', 'cred_vnc', 'cred_ie7', 'sniff_lan', 'migrate_apc', 'spreading_file', 'spreading_share', 'rat_vnc', 'rat_rdp', 'rat_telnet', 'rat_webcam', 'win_mutex', 'win_registry', 'win_token', 'win_private_profile', 'win_files_operation', 'Str_Win32_Winsock2_Library', 'Str_Win32_Wininet_Library', 'Str_Win32_Internet_API', 'Str_Win32_Http_API', 'ldpreload', 'mysql_database_presence']

capabilities_descriptions = ['Code injection with CreateRemoteThread in a remote process', 'Create a new process', 'Install itself for autorun at Windows startup', 'Hijack network configuration', 'Create a windows service', 'Create a COM server', 'Communications over UDP network', 'Listen for incoming communication', 'Communications dyndns network', 'Communications over Toredo network', 'Communications smtp', 'Communications smtp', 'Communications smtp', 'Communications over P2P network', 'Communications over TOR network', 'Communications over IRC network', 'Communications over HTTP', 'File downloader/dropper', 'Communications over FTP', 'Communications over RAW socket', 'Communications use DNS', 'Communications over SSL', 'Communication using dga', 'Perform crypto currency mining', 'Inject certificate in store', 'Privilege Escalation', 'Take screenshot',
                             'Lookup external IP', 'Dynamic DNS', 'Lookup Geolocation', 'Run a keylogger', 'Steal credential', 'Record Audio', 'Steal Firefox credential', 'Steal VNC credential', 'Steal IE 7 credential', 'Sniff Lan network traffic', 'APC queue tasks migration', 'Malware can spread east-west file', 'Malware can spread east-west using share drive', 'Remote Administration toolkit VNC', 'Remote Administration toolkit enable RDP', 'Remote Administration toolkit enable Telnet', 'Remote Administration toolkit using webcam', 'Create or check mutex', 'Affect system registries', 'Affect system token', 'Affect private profile', 'Affect private profile', 'Match Winsock 2 API library declaration', 'Match Windows Inet API library declaration', 'Match Windows Inet API call', 'Match Windows Http API call', 'Load specified shared libraries', 'This rule checks MySQL database presence']

# Capabilities

capabilities_rules_path = yara_rules_path + '/capabilities/'
# The yara.compile() function takes a YARA rules file as input and creates a YARA rules object that can be used to match against files 
# or processes. This object is what allows you to use the YARA rules to scan for matches, by applying them to data and returning the 
# results.
# mele5er rules eli 3andi na3mel menhom objet w nesta3emlou mba3ed bech najem na3mel match (objet kima s =voiture(name)) ama fi blaset 
# name na3ty fichier eli n7eb na3mela analyse kima haka  ==> he4a objet  : rules = yara.compile('rules.yar')
#                                                        ==> he4a lmatch : matches = rules.match(data=data) 
capabilities_rules = yara.compile('/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/'+capabilities_rules_path + 'capabilities.yar')

# Packers

packer_rules_path = yara_rules_path + '/packers/'
packer_compiler_rules = yara.compile('/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/'+packer_rules_path + 'packer_compiler_signatures.yar')



class PEFile:

    def __init__(self,file_path):
        # Yes, that's correct. The lief.parse() function reads the binary file and extracts information from it, such as the header, sections, 
        # imports, exports, and more. This information is then stored in a Binary object which you can use to analyze and modify the binary file.

        # Open file for reading

        binary = lief.parse(file_path.__str__())

        def has_manifest(binary):
            #A manifest is a specific type of resource that provides information about the binary file to the operating system, such as 
            # its version, compatibility requirements, and requested privileges. It is an XML file that is stored as a resource in the 
            # binary.
            if binary.has_resources and not binary.resources_manager.has_manifest:
                return 0
            else:
                return 1
        #ASLR is a security feature that randomizes the memory address space used by an application during runtime, making it more 
        #difficult for attackers to exploit memory-related vulnerabilities.
        #The function first checks whether the binary's optional header has the DLL_CHARACTERISTICS.DYNAMIC_BASE flag set. This flag
        #indicates whether the binary supports ASLR. If the flag is set, the function returns 1, indicating that ASLR is enabled. 
        #Otherwise, it returns 0, indicating that ASLR is not enabled.
        #ASLR allocate a random space in memory to prevent anticipation of address memory space by attacker
        def has_aslr(binary):
            if binary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE):
                return 1
            else:
                return 0
        #Thread Local Storage (TLS) is a mechanism used in software programming that allows each thread of a process to have its own 
        # private storage for data. This data is stored separately from data that is shared between all threads in the process, and can 
        # be accessed and modified only by the thread that owns it.
        def has_tls(binary):
            if binary.has_tls:
                return 1
            else:
                return 0
            
        #Data Execution Prevention (DEP) is a security feature implemented in modern operating systems to prevent malicious code from
        #running in memory. DEP works by marking areas of memory as non-executable, preventing any code from running in those regions.
        #This feature helps to protect against certain types of attacks that exploit vulnerabilities in applications, such as buffer 
        #overflows, by preventing them from executing.
        def has_dep(binary):
            if binary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.NX_COMPAT):
                return 1
            else:
                return 0

        def suspicious_dbgts(binary):
            #==> i4a fama debug [ "debugging" refers to the process of finding and fixing errors or bugs in software code ]
            if binary.has_debug: 
                debug_list = binary.debug
                for item in debug_list:
                    ts = item.timestamp # ==> date taa debug || example of ts :  ts = 1647927255
                    # is a method call in Python's datetime module that converts a Unix timestamp (a number representing the number of 
                    # seconds that have elapsed since January 1, 1970, at 00:00:00 UTC) into a datetime object, which represents a 
                    # specific date and time.
                    dbg_time = datetime.datetime.fromtimestamp(ts) # ==> result :2022-03-21 17:34:15
                    if dbg_time > datetime.datetime.now(): # i4a date debug akber men date taw ma3neha fama ena kifeh ya3mel debug fel mosata9bel 
                        return 1
                return 0 # i4a kamel l boucle w ma l9ach date akber men nhar lyoum ma3neha raja3 0 (3adi ha4eka shyh ma3neha )
            else:
                return -1 # i4a mla9ach aslan debug seb9in donc mayod5elch fel if w directe yet3ada lel else w iraja3 -1

        def check_ci(binary):
            if binary.has_configuration:
                if isinstance(binary.load_configuration, lief.PE.LoadConfigurationV2) and binary.load_configuration.code_integrity.catalog == 0xFFFF:
                    return 0
                else:
                    return 1
            else:
                return -1
        #This code defines a Python function called supports_cfg that takes a Windows Portable Executable (PE) binary file as input and 
        # returns a value indicating whether the binary supports Control Flow Guard (CFG).
        #Control Flow Guard is a security feature introduced in Windows 8.1 and later versions that helps prevent certain types of memory
        #corruption attacks, such as those that use buffer overflows to overwrite function pointers or return addresses. CFG works by 
        #adding extra checks to the binary's control flow graph to ensure that only valid function calls and returns are allowed.
        def supports_cfg(binary):
            if binary.optional_header.has(lief.PE.DLL_CHARACTERISTICS.GUARD_CF):
                return 1
            else:
                return 0
        #returns a value indicating whether the file is digitally signed.
        #Digital signatures are used to verify the authenticity and integrity of a file. They are commonly used to validate software and
        #  driver packages to ensure that they have not been tampered with or modified since they were signed by the original developer.


        def isSigned():
           return 0

                
        #returns a value indicating whether the file is packed.
        
        def isPacked(file_path):
            matches = packer_compiler_rules.match(file_path)
            #example of result of match rules 
            # [
                # RuleMatch(rule='IsPacked', strings=[], namespaces=[], full_name='', tags=set(), meta={}, offset=108642),
                # RuleMatch(rule='HasOverlay', strings=[], namespaces=[], full_name='', tags=set(), meta={}, offset=174080)
            # ]

            matches = [m.rule for m in matches]
            # we can replace this : 
            # rules = []
            # for match in matches:
                # rules.append(match.rule)
                

            if 'IsPacked' in matches:
                return 1
            else:
                return 0

        def calculate_sha256(file_path, block_size=65536):
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for block in iter(lambda: f.read(block_size), b''):
                    sha256.update(block)
            return sha256.hexdigest()
        # This creates a new PE object by calling the PE() constructor of the pefile module, passing in the filename argument as the path 
        # to the PE file to be loaded.The fast_load argument is set to False, which means that the PE file will be fully loaded into 
        # memory, rather than using a faster but less complete loading method. The resulting PE object can be used to inspect and 
        # manipulate the contents of the loaded PE file.
        pe = pefile.PE(file_path, fast_load=False)
        self.file_path = file_path
        self.sha256 = calculate_sha256(file_path)
        self.isSigned = isSigned()

        self.isPacked = isPacked(file_path)

        self.MajorLinkerVersion = pe.OPTIONAL_HEADER.MajorLinkerVersion
        self.MinorLinkerVersion = pe.OPTIONAL_HEADER.MinorLinkerVersion
        self.SizeOfUninitializedData = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        self.ImageBase = pe.OPTIONAL_HEADER.ImageBase
        self.FileAlignment = pe.OPTIONAL_HEADER.FileAlignment
        self.MajorOperatingSystemVersion = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        self.MajorImageVersion = pe.OPTIONAL_HEADER.MajorImageVersion
        self.MinorImageVersion = pe.OPTIONAL_HEADER.MinorImageVersion
        self.MajorSubsystemVersion = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        self.SizeOfImage = pe.OPTIONAL_HEADER.SizeOfImage
        self.SizeOfHeaders = pe.OPTIONAL_HEADER.SizeOfHeaders
        self.CheckSum = pe.OPTIONAL_HEADER.CheckSum
        self.Subsystem = pe.OPTIONAL_HEADER.Subsystem
        self.DllCharacteristics = pe.OPTIONAL_HEADER.DllCharacteristics
        self.SizeOfStackReserve = pe.OPTIONAL_HEADER.SizeOfStackReserve
        self.SizeOfHeapReserve = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        self.NumberOfSections = pe.FILE_HEADER.NumberOfSections
        self.e_cblp = pe.DOS_HEADER.e_cblp
        self.e_lfanew = pe.DOS_HEADER.e_lfanew
        self.SizeOfRawData = sum(map(lambda x: x.SizeOfRawData, pe.sections))
        self.Characteristics = pe.FILE_HEADER.Characteristics
        self.Misc = sum(map(lambda x: x.Misc_VirtualSize, pe.sections))

        try:
            self.BaseOfData = pe.OPTIONAL_HEADER.BaseOfData
        except AttributeError:
            self.BaseOfData = 0

        capabilities = capabilities_rules.match(file_path.__str__())
        capabilities = [capability.rule for capability in capabilities]
            # we can replace this : 
            # capabilities2 = []
            # for capability in capabilities:
                # capabilities2.append(capability.rule)

        for capability in all_capabilities:
            if capability in capabilities:
                setattr(self, capability, 1)
            else:
                setattr(self, capability, 0)



        # Extra Features

        self.has_manifest = has_manifest(binary)
        self.has_aslr = has_aslr(binary)
        self.has_tls = has_tls(binary)
        self.has_dep = has_dep(binary)
        self.code_integrity = check_ci(binary)
        self.supports_cfg = supports_cfg(binary)
        self.suspicious_dbgts = suspicious_dbgts(binary)

        pe.close() # function is called to close the PE file object.
        

    def Build(self):
        item = {}
         # Loops over each attribute (attr) and its corresponding value (k) in the self object's dictionary (__dict__). The self object 
         # refers to an instance of the class in which the Build method is defined.
        for attr, k in self.__dict__.items():
            # Adds each attribute and its value to the item dictionary. Here, the line item[attr] = k assigns the value k to the key attr
            # in the item dictionary.
            item[attr] = k
        return item


def train_model():

    dataset_path = "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/datasets/static.csv"

    df = pd.read_csv(dataset_path, index_col='id')
    #so you use dropna(subset=['family'], inplace=True) to drop all rows where the family column is NaN.
    # The inplace=True parameter is used to modify the DataFrame directly without returning a new copy of the DataFrame
    df.dropna(subset=['family'], inplace=True)
    # calculates the frequency count of each unique value in the family column of the df dataframe.
    threshold = df['family'].value_counts()

    df = df[df.isin(threshold.index[threshold >= 800]).values]

    features = df.columns[2:-1].tolist()

    X = df[features].values
    y = df.iloc[:, -1].values

    le = LabelEncoder()

    y_df = pd.DataFrame(y, dtype=str)
    y_df.apply(le.fit_transform)

    y = y_df.apply(le.fit_transform).values[:, :]

    encoded_labels = dict(zip(le.classes_, le.transform(le.classes_))) #"win32.malware":0 "ransomware":1

    target_names = list(encoded_labels.keys()) #"win32.malware","ransomware"

    X = df[features].values

    class_column = ['family']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.4, random_state=42, stratify=y)

    y_train = y_train.ravel()

    
    
    data = X_train
    scaler = MinMaxScaler()

    scaler.fit(data)

    scaler.transform(data)

    X_train = scaler.transform(data)
    X_test = scaler.transform(X_test)

    xgb_clf = XGBClassifier()
    xgb_clf.fit(X_train, y_train)

    return (xgb_clf, target_names, features, scaler)


if not os.path.exists("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/static.joblib"):
    model, target_names, features, scaler = train_model()
    joblib.dump(model, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/static.joblib")
    joblib.dump(target_names, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/labels/static.joblib")
    joblib.dump(features, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/features/static.joblib")
    joblib.dump(scaler, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/static_scaler.joblib")
else:
    target_names = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/labels/static.joblib")
    model = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/static.joblib")
    features = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/features/static.joblib")    
    scaler = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/static_scaler.joblib")

class Static(Processing):
    """Static analysis."""
    def run(self):
        """Run analysis.
        @return: results dict.
        """
        enabled = True
        
        self.key = "staticML"
        staticML = {}
        
        if self.task["category"] == "file":
            if not os.path.exists(self.file_path):
                return

            f = File(self.file_path)
            filename = os.path.basename(self.task["target"])
        else:
            return

        if filename:
            ext = filename.split(os.path.extsep)[-1].lower()
        else:
            ext = None

        package = self.task.get("package")


        if package == "exe" or ext == "exe" or "PE32" in f.get_type():
            try:
                pe = PEFile(self.file_path)
                sample = pe.Build()
            except Exception as e:
                print(e)
                log.warning("we can't use pe.Build() ")
                return None

            sample_df = pd.DataFrame([sample])

            sample_df.insert(loc=0, column="family", value="-1")

            X_sample = sample_df[features].values

            X_sample = scaler.transform(X_sample)

            predicted_list = model.predict_proba(X_sample)
            result = model.predict(X_sample)[0]
            confidence = round(predicted_list[0][result], 2)

            if result != 0 and X_sample[0][0] == 1:
                result = 0
            
            if result == 0:
                family = target_names[result]
            else:
                family = target_names[result]

            proba= []

            for p,n in zip(predicted_list[0], target_names):
                proba.append("{} : {}".format(n, round(p, 2)))



            list_detected_capabilities=[]
            detected_capabilities = {}

            for index in range(len(all_capabilities)):
                capability = all_capabilities[index]
                description = capabilities_descriptions[index]
                if sample_df[capability][0] == 1:
                    detected_capabilities={"capability": capability, "description": description}
                    list_detected_capabilities.append(detected_capabilities)


            staticML = {
                "proba": proba,
                "family": family,
                "confidence": confidence,
                "detected_capabilities": list_detected_capabilities
            }
                      
        return staticML

