
import os
import PyPDF2
import xml.dom.minidom
import traceback
import math
import operator
import os.path
import sys
import numpy as np
from collections import OrderedDict
import zipfile

if sys.version_info[0] >= 3:
    import urllib.request as urllib23
else:
    import urllib2 as urllib23
if sys.version_info[0] >= 3:
    import configparser as ConfigParser
else:
    import ConfigParser
if sys.version_info[0] >= 3:
    from io import BytesIO as DataIO

import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from xgboost import XGBClassifier
from cuckoo.common.abstracts import Processing
import pandas as pd

from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler

import os
import joblib
import warnings
import logging

warnings.filterwarnings("ignore")
log = logging.getLogger(__name__)

__version__ = "1.0"  # Replace with the appropriate version number


#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string
class cBinaryFile:
    def __init__(self, file, data=None):
        self.file = file
        if data != None:
            self.infile = DataIO(data)
        elif file == '':
            self.infile = sys.stdin
        elif file.lower().startswith('http://') or file.lower().startswith('https://'):
            try:
                if sys.hexversion >= 0x020601F0:
                    self.infile = urllib23.urlopen(file, timeout=5)
                else:
                    self.infile = urllib23.urlopen(file)
            except urllib23.HTTPError:
                print('Error accessing URL %s' % file)
                print(sys.exc_info()[1])
                sys.exit()
        elif file.lower().endswith('.zip'):
            try:
                self.zipfile = zipfile.ZipFile(file, 'r')
                self.infile = self.zipfile.open(self.zipfile.infolist()[0], 'r', C2BIP3('infected'))
            except:
                print('Error opening file %s' % file)
                print(sys.exc_info()[1])
                sys.exit()
        else:
            try:
                self.infile = open(file, 'rb')
            except:
                print('Error opening file %s' % file)
                print(sys.exc_info()[1])
                sys.exit()
        self.ungetted = []

    def byte(self):
        if len(self.ungetted) != 0:
            return self.ungetted.pop()
        inbyte = self.infile.read(1)
        if not inbyte or inbyte == '':
            self.infile.close()
            return None
        return ord(inbyte)

    def bytes(self, size):
        if size <= len(self.ungetted):
            result = self.ungetted[0:size]
            del self.ungetted[0:size]
            return result
        inbytes = self.infile.read(size - len(self.ungetted))
        if inbytes == '':
            self.infile.close()
        if type(inbytes) == type(''):
            result = self.ungetted + [ord(b) for b in inbytes]
        else:
            result = self.ungetted + [b for b in inbytes]
        self.ungetted = []
        return result

    def unget(self, byte):
        self.ungetted.append(byte)

    def ungets(self, bytes):
        bytes.reverse()
        self.ungetted.extend(bytes)
class cPDFDate:
    def __init__(self):
        self.state = 0

    def parse(self, char):
        if char == 'D':
            self.state = 1
            return None
        elif self.state == 1:
            if char == ':':
                self.state = 2
                self.digits1 = ''
            else:
                self.state = 0
            return None
        elif self.state == 2:
            if len(self.digits1) < 14:
                if char >= '0' and char <= '9':
                    self.digits1 += char
                    return None
                else:
                    self.state = 0
                    return None
            elif char == '+' or char == '-' or char == 'Z':
                self.state = 3
                self.digits2 = ''
                self.TZ = char
                return None
            elif char == '"':
                self.state = 0
                self.date = 'D:' + self.digits1
                return self.date
            elif char < '0' or char > '9':
                self.state = 0
                self.date = 'D:' + self.digits1
                return self.date
            else:
                self.state = 0
                return None
        elif self.state == 3:
            if len(self.digits2) < 2:
                if char >= '0' and char <= '9':
                    self.digits2 += char
                    return None
                else:
                    self.state = 0
                    return None
            elif len(self.digits2) == 2:
                if char == "'":
                    self.digits2 += char
                    return None
                else:
                    self.state = 0
                    return None
            elif len(self.digits2) < 5:
                if char >= '0' and char <= '9':
                    self.digits2 += char
                    if len(self.digits2) == 5:
                        self.state = 0
                        self.date = 'D:' + self.digits1 + self.TZ + self.digits2
                        return self.date
                    else:
                        return None
                else:
                    self.state = 0
                    return None
def fEntropy(countByte, countTotal):
    x = float(countByte) / countTotal
    if x > 0:
        return - x * math.log(x, 2)
    else:
        return 0.0
class cEntropy:
    def __init__(self):
        self.allBucket = [0 for i in range(0, 256)]
        self.streamBucket = [0 for i in range(0, 256)]

    def add(self, byte, insideStream):
        self.allBucket[byte] += 1
        if insideStream:
            self.streamBucket[byte] += 1

    def removeInsideStream(self, byte):
        if self.streamBucket[byte] > 0:
            self.streamBucket[byte] -= 1

    def calc(self):
        self.nonStreamBucket = map(operator.sub, self.allBucket, self.streamBucket)
        allCount = sum(self.allBucket)
        streamCount = sum(self.streamBucket)
        nonStreamCount = sum(self.nonStreamBucket)
        if streamCount == 0:
            return (allCount, sum(map(lambda x: fEntropy(x, allCount), self.allBucket)), streamCount, None, nonStreamCount, sum(map(lambda x: fEntropy(x, nonStreamCount), self.nonStreamBucket)))
        else:
            return (allCount, sum(map(lambda x: fEntropy(x, allCount), self.allBucket)), streamCount, sum(map(lambda x: fEntropy(x, streamCount), self.streamBucket)), nonStreamCount, sum(map(lambda x: fEntropy(x, nonStreamCount), self.nonStreamBucket)))
class cPDFEOF:
    def __init__(self):
        self.token = ''
        self.cntEOFs = 0

    def parse(self, char):
        if self.cntEOFs > 0:
            self.cntCharsAfterLastEOF += 1
        if self.token == '' and char == '%':
            self.token += char
            return
        elif self.token == '%' and char == '%':
            self.token += char
            return
        elif self.token == '%%' and char == 'E':
            self.token += char
            return
        elif self.token == '%%E' and char == 'O':
            self.token += char
            return
        elif self.token == '%%EO' and char == 'F':
            self.token += char
            return
        elif self.token == '%%EOF' and (char == '\n' or char == '\r' or char == ' ' or char == '\t'):
            self.cntEOFs += 1
            self.cntCharsAfterLastEOF = 0
            if char == '\n':
                self.token = ''
            else:
                self.token += char
            return
        elif self.token == '%%EOF\r':
            if char == '\n':
                self.cntCharsAfterLastEOF = 0
            self.token = ''
        else:
            self.token = ''
def FindPDFHeaderRelaxed(oBinaryFile):
    bytes = oBinaryFile.bytes(1024)
    index = ''.join([chr(byte) for byte in bytes]).find('%PDF')
    if index == -1:
        oBinaryFile.ungets(bytes)
        return ([], None)
    for endHeader in range(index + 4, index + 4 + 10):
        if bytes[endHeader] == 10 or bytes[endHeader] == 13:
            break
    oBinaryFile.ungets(bytes[endHeader:])
    return (bytes[0:endHeader], ''.join([chr(byte) for byte in bytes[index:endHeader]]))
def Hexcode2String(char):
    if type(char) == int:
        return '#%02x' % char
    else:
        return char
def SwapCase(char):
    if type(char) == int:
        return ord(chr(char).swapcase())
    else:
        return char.swapcase()
def HexcodeName2String(hexcodeName):
    return ''.join(map(Hexcode2String, hexcodeName))
def SwapName(wordExact):
    return map(SwapCase, wordExact)
def UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut):
    if word != '':
        if slash + word in words:
            words[slash + word][0] += 1
            if hexcode:
                words[slash + word][1] += 1
        elif slash == '/' and allNames:
            words[slash + word] = [1, 0]
            if hexcode:
                words[slash + word][1] += 1
        if slash == '/':
            lastName = slash + word
        if slash == '':
            if word == 'stream':
                insideStream = True
            if word == 'endstream':
                if insideStream == True and oEntropy != None:
                    for char in 'endstream':
                        oEntropy.removeInsideStream(ord(char))
                insideStream = False
        if fOut != None:
            if slash == '/' and '/' + word in ('/JS', '/JavaScript', '/AA', '/OpenAction', '/JBIG2Decode', '/RichMedia', '/Launch'):
                wordExactSwapped = HexcodeName2String(SwapName(wordExact))
                fOut.write(C2BIP3(wordExactSwapped))
                print('/%s -> /%s' % (HexcodeName2String(wordExact), wordExactSwapped))
            else:
                fOut.write(C2BIP3(HexcodeName2String(wordExact)))
    return ('', [], False, lastName, insideStream)
class cCVE_2009_3459:
    def __init__(self):
        self.count = 0
    def Check(self, lastName, word):
        if (lastName == '/Colors' and word.isdigit() and int(word) > 2**24): # decided to alert when the number of colors is expressed with more than 3 bytes
            self.count += 1
def XMLAddAttribute(xmlDoc, name, value=None):
    att = xmlDoc.createAttribute(name)
    xmlDoc.documentElement.setAttributeNode(att)
    if value != None:
        att.nodeValue = value
    return att
def GetScriptPath():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(sys.argv[0])
def ParseINIFile():
    oConfigParser = ConfigParser.ConfigParser(allow_no_value=True)
    oConfigParser.optionxform = str
    oConfigParser.read(os.path.join(GetScriptPath(), 'pdfid.ini'))
    keywords = []
    if oConfigParser.has_section('keywords'):
        for key, value in oConfigParser.items('keywords'):
            if not key in keywords:
                keywords.append(key)
    return keywords
def PDFiD(file, allNames=False, extraData=False, disarm=False, force=False, data=None):
    """Example of XML output:
    <PDFiD ErrorOccured="False" ErrorMessage="" Filename="test.pdf" Header="%PDF-1.1" IsPDF="True" Version="0.0.4" Entropy="4.28">
            <Keywords>
                    <Keyword Count="7" HexcodeCount="0" Name="obj"/>
                    <Keyword Count="7" HexcodeCount="0" Name="endobj"/>
                    <Keyword Count="1" HexcodeCount="0" Name="stream"/>
                    <Keyword Count="1" HexcodeCount="0" Name="endstream"/>
                    <Keyword Count="1" HexcodeCount="0" Name="xref"/>
                    <Keyword Count="1" HexcodeCount="0" Name="trailer"/>
                    <Keyword Count="1" HexcodeCount="0" Name="startxref"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/Page"/>
                    <Keyword Count="0" HexcodeCount="0" Name="/Encrypt"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/JS"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/JavaScript"/>
                    <Keyword Count="0" HexcodeCount="0" Name="/AA"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/OpenAction"/>
                    <Keyword Count="0" HexcodeCount="0" Name="/JBIG2Decode"/>
            </Keywords>
            <Dates>
                    <Date Value="D:20090128132916+01'00" Name="/ModDate"/>
            </Dates>
    </PDFiD>
    """

    word = ''
    wordExact = []
    hexcode = False
    lastName = ''
    insideStream = False
    keywords = ['obj',
                'endobj',
                'stream',
                'endstream',
                'xref',
                'trailer',
                'startxref',
                '/Page',
                '/Encrypt',
                '/ObjStm',
                '/JS',
                '/JavaScript',
                '/AA',
                '/OpenAction',
                '/AcroForm',
                '/JBIG2Decode',
                '/RichMedia',
                '/Launch',
                '/EmbeddedFile',
                '/XFA',
               ]
    words = {}
    dates = []
    for extrakeyword in ParseINIFile():
        if not extrakeyword in keywords:
            keywords.append(extrakeyword)
    for keyword in keywords:
        words[keyword] = [0, 0]
    slash = ''
    xmlDoc = xml.dom.minidom.getDOMImplementation().createDocument(None, 'PDFiD', None)
    XMLAddAttribute(xmlDoc, 'Version', __version__)
    XMLAddAttribute(xmlDoc, 'Filename', file)
    attErrorOccured = XMLAddAttribute(xmlDoc, 'ErrorOccured', 'False')
    attErrorMessage = XMLAddAttribute(xmlDoc, 'ErrorMessage', '')

    oPDFDate = None
    oEntropy = None
    oPDFEOF = None
    oCVE_2009_3459 = cCVE_2009_3459()
    try:
        attIsPDF = xmlDoc.createAttribute('IsPDF')
        xmlDoc.documentElement.setAttributeNode(attIsPDF)
        oBinaryFile = cBinaryFile(file, data)
        if extraData:
            oPDFDate = cPDFDate()
            oEntropy = cEntropy()
            oPDFEOF = cPDFEOF()
        (bytesHeader, pdfHeader) = FindPDFHeaderRelaxed(oBinaryFile)
        if disarm:
            (pathfile, extension) = os.path.splitext(file)
            fOut = open(pathfile + '.disarmed' + extension, 'wb')
            for byteHeader in bytesHeader:
                fOut.write(C2BIP3(chr(byteHeader)))
        else:
            fOut = None
        if oEntropy != None:
            for byteHeader in bytesHeader:
                oEntropy.add(byteHeader, insideStream)
        if pdfHeader == None and not force:
            attIsPDF.nodeValue = 'False'
            return xmlDoc
        else:
            if pdfHeader == None:
                attIsPDF.nodeValue = 'False'
                pdfHeader = ''
            else:
                attIsPDF.nodeValue = 'True'
            att = xmlDoc.createAttribute('Header')
            att.nodeValue = repr(pdfHeader[0:10]).strip("'")
            xmlDoc.documentElement.setAttributeNode(att)
        byte = oBinaryFile.byte()
        while byte != None:
            char = chr(byte)
            charUpper = char.upper()
            if charUpper >= 'A' and charUpper <= 'Z' or charUpper >= '0' and charUpper <= '9':
                word += char
                wordExact.append(char)
            elif slash == '/' and char == '#':
                d1 = oBinaryFile.byte()
                if d1 != None:
                    d2 = oBinaryFile.byte()
                    if d2 != None and (chr(d1) >= '0' and chr(d1) <= '9' or chr(d1).upper() >= 'A' and chr(d1).upper() <= 'F') and (chr(d2) >= '0' and chr(d2) <= '9' or chr(d2).upper() >= 'A' and chr(d2).upper() <= 'F'):
                        word += chr(int(chr(d1) + chr(d2), 16))
                        wordExact.append(int(chr(d1) + chr(d2), 16))
                        hexcode = True
                        if oEntropy != None:
                            oEntropy.add(d1, insideStream)
                            oEntropy.add(d2, insideStream)
                        if oPDFEOF != None:
                            oPDFEOF.parse(d1)
                            oPDFEOF.parse(d2)
                    else:
                        oBinaryFile.unget(d2)
                        oBinaryFile.unget(d1)
                        (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut)
                        if disarm:
                            fOut.write(C2BIP3(char))
                else:
                    oBinaryFile.unget(d1)
                    (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut)
                    if disarm:
                        fOut.write(C2BIP3(char))
            else:
                oCVE_2009_3459.Check(lastName, word)

                (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut)
                if char == '/':
                    slash = '/'
                else:
                    slash = ''
                if disarm:
                    fOut.write(C2BIP3(char))

            if oPDFDate != None and oPDFDate.parse(char) != None:
                dates.append([oPDFDate.date, lastName])

            if oEntropy != None:
                oEntropy.add(byte, insideStream)

            if oPDFEOF != None:
                oPDFEOF.parse(char)

            byte = oBinaryFile.byte()
        (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut)

        # check to see if file ended with %%EOF.  If so, we can reset charsAfterLastEOF and add one to EOF count.  This is never performed in
        # the parse function because it never gets called due to hitting the end of file.
        if byte == None and oPDFEOF != None:
            if oPDFEOF.token == '%%EOF':
                oPDFEOF.cntEOFs += 1
                oPDFEOF.cntCharsAfterLastEOF = 0
                oPDFEOF.token = ''

    except SystemExit:
        sys.exit()
    except:
        attErrorOccured.nodeValue = 'True'
        attErrorMessage.nodeValue = traceback.format_exc()

    if disarm:
        fOut.close()

    attEntropyAll = xmlDoc.createAttribute('TotalEntropy')
    xmlDoc.documentElement.setAttributeNode(attEntropyAll)
    attCountAll = xmlDoc.createAttribute('TotalCount')
    xmlDoc.documentElement.setAttributeNode(attCountAll)
    attEntropyStream = xmlDoc.createAttribute('StreamEntropy')
    xmlDoc.documentElement.setAttributeNode(attEntropyStream)
    attCountStream = xmlDoc.createAttribute('StreamCount')
    xmlDoc.documentElement.setAttributeNode(attCountStream)
    attEntropyNonStream = xmlDoc.createAttribute('NonStreamEntropy')
    xmlDoc.documentElement.setAttributeNode(attEntropyNonStream)
    attCountNonStream = xmlDoc.createAttribute('NonStreamCount')
    xmlDoc.documentElement.setAttributeNode(attCountNonStream)
    if oEntropy != None:
        (countAll, entropyAll , countStream, entropyStream, countNonStream, entropyNonStream) = oEntropy.calc()
        attEntropyAll.nodeValue = '%f' % entropyAll
        attCountAll.nodeValue = '%d' % countAll
        if entropyStream == None:
            attEntropyStream.nodeValue = 'N/A     '
        else:
            attEntropyStream.nodeValue = '%f' % entropyStream
        attCountStream.nodeValue = '%d' % countStream
        attEntropyNonStream.nodeValue = '%f' % entropyNonStream
        attCountNonStream.nodeValue = '%d' % countNonStream
    else:
        attEntropyAll.nodeValue = ''
        attCountAll.nodeValue = ''
        attEntropyStream.nodeValue = ''
        attCountStream.nodeValue = ''
        attEntropyNonStream.nodeValue = ''
        attCountNonStream.nodeValue = ''
    attCountEOF = xmlDoc.createAttribute('CountEOF')
    xmlDoc.documentElement.setAttributeNode(attCountEOF)
    attCountCharsAfterLastEOF = xmlDoc.createAttribute('CountCharsAfterLastEOF')
    xmlDoc.documentElement.setAttributeNode(attCountCharsAfterLastEOF)
    if oPDFEOF != None:
        attCountEOF.nodeValue = '%d' % oPDFEOF.cntEOFs
        if oPDFEOF.cntEOFs > 0:
            attCountCharsAfterLastEOF.nodeValue = '%d' % oPDFEOF.cntCharsAfterLastEOF
        else:
            attCountCharsAfterLastEOF.nodeValue = ''
    else:
        attCountEOF.nodeValue = ''
        attCountCharsAfterLastEOF.nodeValue = ''

    eleKeywords = xmlDoc.createElement('Keywords')
    xmlDoc.documentElement.appendChild(eleKeywords)
    for keyword in keywords:
        eleKeyword = xmlDoc.createElement('Keyword')
        eleKeywords.appendChild(eleKeyword)
        att = xmlDoc.createAttribute('Name')
        att.nodeValue = keyword
        eleKeyword.setAttributeNode(att)
        att = xmlDoc.createAttribute('Count')
        att.nodeValue = str(words[keyword][0])
        eleKeyword.setAttributeNode(att)
        att = xmlDoc.createAttribute('HexcodeCount')
        att.nodeValue = str(words[keyword][1])
        eleKeyword.setAttributeNode(att)
    eleKeyword = xmlDoc.createElement('Keyword')
    eleKeywords.appendChild(eleKeyword)
    att = xmlDoc.createAttribute('Name')
    att.nodeValue = '/Colors > 2^24'
    eleKeyword.setAttributeNode(att)
    att = xmlDoc.createAttribute('Count')
    att.nodeValue = str(oCVE_2009_3459.count)
    eleKeyword.setAttributeNode(att)
    att = xmlDoc.createAttribute('HexcodeCount')
    att.nodeValue = str(0)
    eleKeyword.setAttributeNode(att)
    if allNames:
        keys = sorted(words.keys())
        for word in keys:
            if not word in keywords:
                eleKeyword = xmlDoc.createElement('Keyword')
                eleKeywords.appendChild(eleKeyword)
                att = xmlDoc.createAttribute('Name')
                att.nodeValue = word
                eleKeyword.setAttributeNode(att)
                att = xmlDoc.createAttribute('Count')
                att.nodeValue = str(words[word][0])
                eleKeyword.setAttributeNode(att)
                att = xmlDoc.createAttribute('HexcodeCount')
                att.nodeValue = str(words[word][1])
                eleKeyword.setAttributeNode(att)
    eleDates = xmlDoc.createElement('Dates')
    xmlDoc.documentElement.appendChild(eleDates)
    dates.sort(key=lambda x: x[0])
    for date in dates:
        eleDate = xmlDoc.createElement('Date')
        eleDates.appendChild(eleDate)
        att = xmlDoc.createAttribute('Value')
        att.nodeValue = date[0]
        eleDate.setAttributeNode(att)
        att = xmlDoc.createAttribute('Name')
        att.nodeValue = date[1]
        eleDate.setAttributeNode(att)
    return xmlDoc

def count_images(pdf_path):
    with open(pdf_path, 'rb') as f:
        pdf_reader = PyPDF2.PdfFileReader(f)
        num_pages = pdf_reader.getNumPages()
        num_images = 0
        
        for i in range(num_pages):
            page = pdf_reader.getPage(i)
            if '/XObject' in page['/Resources']:
                xobjects = page['/Resources']['/XObject'].getObject()
                if xobjects is not None:
                    for obj in xobjects:
                        if xobjects[obj]['/Subtype'] == '/Image':
                            num_images += 1
        
        return num_images


def text(pdf_path):
    with open(pdf_path, 'rb') as f:
        pdf_reader = PyPDF2.PdfFileReader(f)
        for page in pdf_reader.pages:
            text = page.extract_text()
            if text:
                return "Yes"
    return "No"
def pdfsize(filepath):
    if os.path.isfile(filepath) and filepath.endswith('.pdf'):
        file_size = os.path.getsize(filepath)
        return file_size
    else:
        return 0
def metadata_size(filepath):
    with open(filepath, 'rb') as f:
        pdf_reader = PyPDF2.PdfFileReader(f)
        metadata = pdf_reader.getDocumentInfo()
        metadata_length = 0
        for key, value in metadata.items():
            if value is not None:
                metadata_length = metadata_length + len(value)
        return metadata_length
def title_characters(filepath):
    with open(filepath, 'rb') as f:
        pdf_reader = PyPDF2.PdfFileReader(f)
        title = pdf_reader.getDocumentInfo().title
        if title:
            return len(title)
        else:
            return 0

def count_xref_length(filepath):
    with open(filepath, 'rb') as f:
        pdf_reader = PyPDF2.PdfFileReader(f)
        xref_length = 0

        # Find the xref table
        for i in range(pdf_reader.numPages):
            page = pdf_reader.getPage(i)
            if '/XRef' in page.extract_text():
                xref_length = int(page.extract_text().split('/Size')[1].split('/')[0])
                break

        return xref_length

def count_xref_length(filepath):
    with open(filepath, 'rb') as f:
        pdf_reader = PyPDF2.PdfFileReader(f)

        # Get the trailer dictionary
        trailer = pdf_reader.trailer
        startxref_offset = trailer.get('/XRefStm', trailer.get('/Prev'))

        if startxref_offset is not None:
            # Go to the startxref offset
            f.seek(startxref_offset, 0)

            # Read the xref table
            xref_data = f.read()

            # Count the length of the xref table
            xref_length = xref_data.count(b'xref') - 1

            return xref_length
        else:
            return 0

def PDFiD2Dict(xmlDoc,file_path):
    result = OrderedDict()

    for node in xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes:
        keyword_name = node.getAttribute('Name')
        keyword_count = int(node.getAttribute('Count'))
        result[keyword_name] =  keyword_count

    result['PDFHeader'] = '\t' + xmlDoc.documentElement.getAttribute('Header')
    result['text'] = text(file_path)
    result['images'] = count_images(file_path)
    result['pdfsize'] = pdfsize(file_path)
    result['metadatasize'] = metadata_size(file_path)
    result['titlecharacters'] = title_characters(file_path)
    result['xrefLength'] =  count_xref_length(file_path)
    

    result_final = OrderedDict()
    order = ['pdfsize', 'metadatasize', '/Page','xrefLength', 'titlecharacters', '/Encrypt', 'images', 'text','PDFHeader', 'obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref', 
    '/ObjStm', '/JS','/JavaScript', '/AA', '/OpenAction', '/AcroForm', '/JBIG2Decode', '/RichMedia', '/Launch','/EmbeddedFile', '/XFA','/Colors > 2^24']
    
    for key in order:
        if key in result:
            result_final[key] = result[key]

    return result_final


def train_model():

    dataset_path = "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/datasets/pdfdatasetfinale.csv"
    df = pd.read_csv(dataset_path)
    df.dropna(subset=['Class'], inplace=True)
    text_label = LabelEncoder()
    df['text'] = text_label.fit_transform(df['text'])
    PDFHeader_label = LabelEncoder()
    df["PDFHeader"] = PDFHeader_label.fit_transform(df["PDFHeader"])
    features = df.columns[1:-1]
    X = df[features].values
    y = df.iloc[:, -1].values
    le = LabelEncoder()
    y_df = pd.DataFrame(y, dtype=str)
    y_df.apply(le.fit_transform)
    y = y_df.apply(le.fit_transform).values[:, :]
    encoded_labels = dict(zip(le.classes_, le.transform(le.classes_))) 
    target_names = list(encoded_labels.keys()) 
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    y_train = y_train.ravel()
    data = X_train
    scaler = MinMaxScaler()
    scaler.fit(data)
    scaler.transform(data)
    X_train = scaler.transform(data)
    X_test = scaler.transform(X_test)

    xgb_clf = XGBClassifier()
    xgb_clf.fit(X_train, y_train)

    return (xgb_clf, target_names, features, scaler,text_label,PDFHeader_label)


if not os.path.exists("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/pdf.joblib"):
    model, target_names, features, scaler,text_label,PDFHeader_label = train_model()
    joblib.dump(model, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/pdf.joblib")
    joblib.dump(target_names, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/labels/pdf.joblib")
    joblib.dump(text_label, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/labels/text_label.joblib")
    joblib.dump(PDFHeader_label, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/labels/PDFHeader_label.joblib")
    joblib.dump(features, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/features/pdf.joblib")
    joblib.dump(scaler, "/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/pdf_scaler.joblib")
else:
    target_names = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/labels/pdf.joblib")
    text_label = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/labels/text_label.joblib")
    PDFHeader_label = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/labels/PDFHeader_label.joblib")
    model = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/pdf.joblib")
    features = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/features/pdf.joblib")    
    scaler = joblib.load("/home/cuckoo/.virtualenvs/cuckoo-cuckoo/lib/python2.7/site-packages/cuckoo/processing/models/pdf_scaler.joblib")





class Static(Processing):
    """Static analysis."""
    def run(self):
        """Run analysis.
        @return: results dict.
        """
        enabled = True
        
        self.key = "pdfML"
        pdfML = {}
        
        if self.task["category"] == "file":
            if not os.path.exists(self.file_path):
                return
            
            filename = os.path.basename(self.task["target"])
        else:
            return

        if filename:
            ext = filename.split(os.path.extsep)[-1].lower()
        else:
            ext = None

        package = self.task.get("package")


        if package == "pdf" or ext == "pdf":
            
            try:
                xmlDoc=PDFiD(self.file_path)
                
            except Exception as e:
                print(e)
                log.warning("we can't analyse pdf file ")
                return None
            sample=PDFiD2Dict(xmlDoc,self.file_path)
            sample_df = pd.DataFrame([sample])

            sample_df['Class'] = "-1"

            text_column_index = np.where(features == 'text')[0][0]
            PDFHeader_column_index = np.where(features == 'PDFHeader')[0][0]
            X_sample = sample_df[features].values
            X_sample[:, text_column_index] = text_label.fit_transform(X_sample[:, text_column_index])
            X_sample[:, PDFHeader_column_index] = PDFHeader_label.fit_transform(X_sample[:, PDFHeader_column_index])
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



            list = []
            dict = {}
            for key, value in sample.items():
                dict={"key": key, "value": value}
                list.append(dict)

            pdfML = {
                "proba": proba,
                "family": family,
                "confidence": confidence,
                "features":list
            }
                      
        return pdfML


