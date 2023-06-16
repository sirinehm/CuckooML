# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
from sklearn.preprocessing import LabelEncoder
import bs4
import numpy as np
import ctypes
import datetime
import logging
import oletools.olevba
import oletools.oleobj
import os
import peepdf.JSAnalysis
import peepdf.PDFCore
import pefile
import peutils
import re
import sflock
import struct
import zipfile
import zlib
import pandas as pd
import pandas as pd
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
import joblib
try:
    import M2Crypto
    HAVE_MCRYPTO = True
except ImportError:
    HAVE_MCRYPTO = False

from cuckoo.common.abstracts import Processing
from cuckoo.common.objects import Archive, File
from cuckoo.common.structures import LnkHeader, LnkEntry
from cuckoo.common.utils import convert_to_printable, to_unicode, jsbeautify
from cuckoo.core.extract import ExtractManager
from cuckoo.misc import cwd, dispatch

from elftools.common.exceptions import ELFError
from elftools.elf.constants import E_FLAGS
from elftools.elf.descriptions import (
    describe_ei_class, describe_ei_data, describe_ei_version,
    describe_ei_osabi, describe_e_type, describe_e_machine,
    describe_e_version_numeric, describe_p_type, describe_p_flags,
    describe_sh_type, describe_dyn_tag, describe_symbol_type,
    describe_symbol_bind, describe_note, describe_reloc_type
)
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_D_TAG
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from elftools.elf.segments import NoteSegment

log = logging.getLogger(__name__)

# Partially taken from
# http://malwarecookbook.googlecode.com/svn/trunk/3/8/pescanner.py

class PortableExecutable(object):
    """PE analysis."""

    def __init__(self, file_path):
        """@param file_path: file path."""
        self.file_path = file_path
        self.pe = None

    def _get_filetype(self, data):
        """Get filetype, use libmagic if available.
        @param data: data to be analyzed.
        @return: file type or None.
        """
        return sflock.magic.from_buffer(data)

    def _get_imported_symbols(self):
        """Get imported symbols.
        @return: imported symbols dict or None.
        """
        imports = []

        for entry in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []):
            try:
                symbols = []
                for imported_symbol in entry.imports:
                    symbols.append({
                        "address": hex(imported_symbol.address),
                        "name": imported_symbol.name,
                    })

                imports.append({
                    "dll": convert_to_printable(entry.dll),
                    "imports": symbols,
                })
            except:
                log.exception("Unable to parse imported symbols.")

        return imports

    def _get_exported_symbols(self):
        """Get exported symbols.
        @return: exported symbols dict or None.
        """
        exports = []

        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            for exported_symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append({
                    "address": hex(self.pe.OPTIONAL_HEADER.ImageBase +
                                   exported_symbol.address),
                    "name": exported_symbol.name,
                    "ordinal": exported_symbol.ordinal,
                })

        return exports

    def run(self):
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not os.path.exists(self.file_path):
            return {}

        try:
            self.pe = pefile.PE(self.file_path)
        except pefile.PEFormatError:
            return {}

        results = {}
        results["pe_imports"] = self._get_imported_symbols()
        results["pe_exports"] = self._get_exported_symbols()
        return results

def train_model():
    dataset_path = "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/datasets/top_1000_pe_imports.csv"
    df = pd.read_csv(dataset_path)

    df.loc[df['malware'] == 0, 'malware'] = "benign"
    df.loc[df['malware'] == 1, 'malware'] = "malware"

    df.dropna(subset=['malware'], inplace=True)
    threshold = df['malware'].value_counts()

    df = df[df.isin(threshold.index[threshold >= 800]).values]

    features = df.columns[1:-1].tolist()
    X = df[features].values
    y = df.iloc[:, -1].values
    

    le = LabelEncoder()

    y_df = pd.DataFrame(y, dtype=str)
    y_df.apply(le.fit_transform)

    y = y_df.apply(le.fit_transform).values[:, :]

    encoded_labels = dict(zip(le.classes_, le.transform(le.classes_)))

    target_names = list(encoded_labels.keys())

    X = df[features].values

    class_column = ['family']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    xgb_clf = XGBClassifier()
    xgb_clf.fit(X_train, y_train)

    return (xgb_clf, target_names, features)


if not os.path.exists("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/imports.joblib"):
    model, target_names, features = train_model()
    joblib.dump(model, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/imports.joblib")
    joblib.dump(target_names, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/labels/imports.joblib")
    joblib.dump(features, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/features/imports.joblib")
else:
    target_names = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/labels/imports.joblib")
    model = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/imports.joblib")
    features = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/features/imports.joblib")

class Static(Processing):
    """Static analysis."""


    def run(self):
        """Run analysis.
        @return: results dict.
        """
        self.key = "importss"
        importsML = {}
        importss = {}

        if self.task["category"] == "file":
            if not os.path.exists(self.file_path):
                return

            f = File(self.file_path)
            filename = os.path.basename(self.task["target"])
        elif self.task["category"] == "archive":
            if not os.path.exists(self.file_path):
                return

            f = Archive(self.file_path).get_file(
                self.task["options"]["filename"]
            )
            filename = os.path.basename(self.task["options"]["filename"])
        else:
            return

        if filename:
            ext = filename.split(os.path.extsep)[-1].lower()
        else:
            ext = None

        package = self.task.get("package")

        if package == "exe" or ext == "exe" or "PE32" in f.get_type():
            importsML.update(PortableExecutable(f.file_path).run())
            importsML["keys"] = f.get_keys()

        import_fct = []
        for import_dict in importsML["pe_imports"]:
            for imp in import_dict["imports"]:
                if imp['name'] is not None or imp['name']=='null' :
                    import_fct.append(imp['name'])
        exmport_fct = []
        for import_dict in importsML["pe_imports"]:
            for imp in import_dict["imports"]:
                if imp['name'] is not None or imp['name']=='null' :
                    exmport_fct.append(imp['name'])

        
        class_ = 'malware'

        imports =  import_fct + exmport_fct + [class_] 
        
            
        data_df = pd.DataFrame(np.array(imports).reshape(1, -1))
            
        df = pd.DataFrame(0, index=np.arange(len(data_df)), columns=features + ["malware"])

        for i in range(len(data_df.values)):
            df.iloc[i, -1] = data_df.values[i][-1]
            for value in data_df.values[i][:-1]:
                if type(value) != str:
                    continue
                if not value in features:
                    continue
                df.loc[i, value] = 1
                        
        X_sample = df.values[:,:-1]
        y = df.values[:,-1:]

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






        # Add the importss section to the report
        importss = {
            "proba": proba,
            "family": family,
            "confidence": confidence
        }


        return importss

