# -*- coding: utf-8 -*-
import sys
import time
import pandas as pd
import clr
import System
import re
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import QFileInfo
from PyQt5.QtGui import QIcon
# from PyQt5.QtWidgets import *
from PyQt5.QtWidgets import QMessageBox, QFileDialog, QMainWindow, QDialog, QCheckBox, QListWidgetItem, QLineEdit
from System import Enum
from System import Array
from IL_Sample_Gui import Ui_IL_Sample
from IL_Sample_sweeping_Gui import Ui_IL_Sweeping_Sample

assembly_path = r".\InstrumentDLL"
sys.path.append(assembly_path)
ref = clr.AddReference(r"InstrumentDLL")

assembly_path = r".\STSProcessDLL"
sys.path.append(assembly_path)
ref = clr.AddReference(r"STSProcess")

assembly_path = r".\FTD2XX_NET"
sys.path.append(assembly_path)
ref = clr.AddReference(r"FTD2XX_NET")

# import DLL namespace
from Santec import *
from Santec.Communication import *
from Santec.Instruments import *
from Santec.STSProcess import *
from Santec.Rescaling_Process import *

# instance of DLL's class
tsl_ = TSL()
spu_ = SPU()
Cal_STS = ILSTS()
mpms = []
connectTypes = []
checkedChannels = []

Flag_215 = False
Flag_213 = False
Flag_570 = False
inst_flag = False
mpmLoggData = None

errorInfo = {-2147483648:"Unknown", -40:"InUseError", -30:"ParameterError", 
             -20:"DeviceError", -14:"CommunicationFailure", 
             -13:"UnauthorizedAccess", -12:"IOException",
             -11:"NotConnected", -10:"Uninitialized",
             -2:"TimeOut", -1:"Failure", -5:"Count_mismatch",
             -6:"MonitorError", 0:"Succeed", 11:"AlreadyConnected",
             10:"Stopped"}

# data struct for STS
measure_data = []  # list of measurement data
reference_data = []  # list of reference data
measure_monitor_data = []  # list of  measurement monitor data
reference_monitor_data = []  # list of reference monitor data
merge_data = []  # list of merge data

Meas_rang = []
Data_struct = []
Refdata_struct = []
Ref_monitordata_struct=[]
Meas_monitor_struct = []
Mergedata_struct = []
Ref_monitor_struct = None

# show instrument error
def show_instrument_error(errorcode):
    msg = errorInfo.get(errordata)
    QMessageBox.warning(None, 'Waring', msg, QMessageBox.Ok)
    return

# show pdl sts error
def show_sts_error(errorcode):
    msg = errorInfo.get(errordata)
    QMessageBox.warning(None, 'Waring', msg, QMessageBox.Ok)
    return

# gets the USB resource connected to the PC
def get_usb_resource():
    IL_form.cmb_tsl_usb.clear()
    usb_com = MainCommunication.Get_USB_Resouce()
    return usb_com

# gets the TSL USB resource connected to the PC
def get_tsl_usb_resource():
    usb_res = get_usb_resource()
    IL_form.cmb_tsl_usb.addItems(usb_res)

# gets the PCU USB resource connected to the PC
def get_pcu_usb_resource():
    usb_res = get_usb_resource()

# gets the DAQ ID
def get_daq_id():
    IL_form.cmb_dev_number.clear()
    error_code, dev_ID = spu_.Get_Device_ID([])
    if error_code != 0:
        show_instrument_error(error_code)
        return
    IL_form.cmb_dev_number.addItems(dev_ID)

class IL_Window(QMainWindow, Ui_IL_Sample):
    def __init__(self, parent=None):
        super(IL_Window, self).__init__(parent)
        self.setupUi(self)
        self.init_ui()

    def init_ui(self):
        self.rdo_tsl570.setChecked(True)
        self.rdo_tsl_gpib.setChecked(True)
        self.txt_tsl_ip.setDisabled(True)
        self.txt_tsl_port.setDisabled(True)
        self.cmb_tsl_usb.setDisabled(True)
        self.rdo_mpm_gpib.setChecked(True)
        self.txt_mpm_ip.setDisabled(True)
        self.txt_mpm_port.setDisabled(True)
        self.txt_mpm_gpib_board.setText("0")
        self.txt_tsl_gpib_board.setText("0")
        self.txt_tsl_port.setText("5000")
        self.txt_mpm_port.setText("5000")
        self.btn_add_device.clicked.connect(on_add_device)
        self.btn_delete_device.clicked.connect(on_del_device)
        self.btn_connect.clicked.connect(on_connect)
        self.btn_disconnect.clicked.connect(on_disconnect)
        
class IL_Sweeping_Window(QDialog, Ui_IL_Sweeping_Sample):
    def __init__(self):
        super(IL_Sweeping_Window, self).__init__()
        self.setupUi(self)
        self.init_ui()

    def init_ui(self):
        self.btn_Set.clicked.connect(set_parameterformeasure)
        self.btn_reference.clicked.connect(reference)
        self.btn_measurement.clicked.connect(measure)
        self.btn_saverefrawdata.clicked.connect(save_reference_raw_data)
        self.btn_saverawdata.clicked.connect(save_raw_data)
        self.btn_readrefrawdata.clicked.connect(read_reference_raw_data)


def save_reference_raw_data():

    global Refdata_struct
    global Ref_monitordata_struct
    
    lstpowdata = []
    lstmonitordata = []
    for item in Refdata_struct:
        process_error, powdata = Cal_STS.Get_Ref_Power_Rawdata(item, None)
        if process_error != 0:
            Show_STS_Error(process_error)
            return

        lstpowdata.append(powdata)

    befor_struct = STSDataStruct()
    for item in Ref_monitordata_struct:

        if IL_form.IL_Sweeping_form.chkeach_ch.isChecked():

            if item.MPMNumber == befor_struct.MPMNumber and item.SlotNumber == befor_struct.SlotNumber and item.ChannelNumber == befor_struct.ChannelNumber:
                continue

        process_error, monitordata = Cal_STS.Get_Ref_Monitor_Rawdata(item, None)

        if process_error != 0:
            Show_STS_Error(process_error)
            return

        get_struct = STSDataStruct()
        get_struct.MPMNumber = item.MPMNumber
        get_struct.SlotNumber = item.SlotNumber
        get_struct.ChannelNumber = item.ChannelNumber

        lstmonitordata.append(monitordata)
        befor_struct = get_struct

    process_error, wavetable = Cal_STS.Get_Target_Wavelength_Table(None)

    if process_error != 0:
        Show_STS_Error(process_error)
        return

    hedder = []
    hedder.append("Wavelength(nm)")

    for item in Data_struct:
        if item.SweepCount != 1:
            continue

        hedder.append("MPM" + str(item.MPMNumber) + "Slot" + str(item.SlotNumber) + "Ch" + str(item.ChannelNumber))

    loop1 = 0
    if IL_form.IL_Sweeping_form.chkeach_ch.isChecked():

        for item in Refdata_struct:
            if item.SOP != loop1:
                continue

            hedder.append("monitordata_MPM" + str(item.MPMNumber) + "Slot" + str(item.SlotNumber) + "Ch" + str(item.ChannelNumber))
    else:
        hedder.append("monitordata")

    result = []
    for loop1 in range(len(wavetable)):

        data = []
        data.append(wavetable[loop1])

        for powdata in lstpowdata:
            data.append(powdata[loop1])

        for monitor in lstmonitordata:
            data.append(monitor[loop1])

        result.append(data)
        
    file_path = save_function()
    
    cal_result = pd.DataFrame(result, columns=hedder)
    cal_result.to_csv(file_path, index=False)

    QMessageBox.information(None, 'Information', 'Completed.', QMessageBox.Ok)

def save_raw_data():
    
    errorcode, wavelength_table = Cal_STS.Get_Target_Wavelength_Table(None)

    if errorcode != 0:
        Show_STS_Error(errorcode)
        return

    for loop1 in range(len(Meas_rang)):
        lstpower = []
        for item in Data_struct:

            if item.RangeNumber != Meas_rang[loop1]:
                continue

            errorcode, powerdata = Cal_STS.Get_Meas_Power_Rawdata(item, None)

            if errorcode != 0:
                Show_STS_Error(errorcode)
                return

            lstpower.append(powerdata)

        for monitoritem in Meas_monitor_struct:

            if monitoritem.SweepCount == loop1 + 1:
                errorcode, monitordata = Cal_STS.Get_Meas_Monitor_Rawdata(monitoritem, None)
            else:
                continue
        
        result = []
        header = []
        for rowIndex in range(len(wavelength_table)):
            if rowIndex == 0:
                header.append("wavelength")
            data = []
            data.append(wavelength_table[rowIndex])
            for colIndex in range(len(lstpower)):
                
                if rowIndex == 0:
                    item = Data_struct[colIndex]
                    header.append("MPM" + str(item.MPMNumber) + "Slot" + str(item.SlotNumber) + "Ch" + str(item.ChannelNumber))
                
                tempData = lstpower[colIndex]
                data.append(tempData[rowIndex])
            
            if rowIndex == 0:
                header.append("Monitordata")
                
            data.append(monitordata[rowIndex])
            result.append(data)
            
        file_path = save_function()
        
        cal_result = pd.DataFrame(result, columns=header)
        cal_result.to_csv(file_path, index=False)

    QMessageBox.information(None, 'information', 'Completed.', QMessageBox.Ok)

def read_reference_raw_data():
    options = QFileDialog.Options()
    options |= QFileDialog.DontUseNativeDialog
    path= QFileDialog.getOpenFileName(None, "Save data", "", "*.csv", options=options)
    read_data = pd.read_csv(path[0])
    
    if IL_form.IL_Sweeping_form.chkeach_ch.isChecked():
        ch_count = (len(read_data.columns) - 1) / 2
    else:
        ch_count = len(read_data.columns) - 2

    if ch_count != len(checkedChannels):

        QMessageBox.information(None, 'warning', 'Reference data mismatch.Please selecet right data.', QMessageBox.Ok)
        return

    if IL_form.IL_Sweeping_form.chkeach_ch.isChecked():
        
        for loop1 in range(1, int(ch_count) + 1):
    
            tempHeader = read_data.columns[loop1]

            chk_str = tempHeader[3:4]
            mpm_number = int(chk_str)
            
            chk_str = tempHeader[8:9]
            slot_number = int(chk_str)
    
            chk_str = tempHeader[11:12]
            ch_number = int(chk_str)
    
            for item in Data_struct:
    
                if item.MPMNumber == mpm_number and item.SlotNumber == slot_number and item.ChannelNumber == ch_number:
                    match_flag = True
                    break
    
            if match_flag == False:
                QMessageBox.information(None, 'warning', 'Reference data mismatch.Please selecet right data.', QMessageBox.Ok)
                return
            
            lstWave = read_data[read_data.columns[0]].to_list()
            if lstWave[len(lstWave) - 1] != float(IL_form.IL_Sweeping_form.txt_stopwave.text()):
                QMessageBox.information(None, 'warning', 'Reference data mismatch.Please selecet right data.', QMessageBox.Ok)
                return
    
            lstPower = read_data[tempHeader].to_list()
            
            tempMonitorHeader = read_data.columns[loop1 + int(ch_count)]
            lstMonitor = read_data[tempMonitorHeader].to_list()
            
            datapoint = (float(IL_form.IL_Sweeping_form.txt_stopwave.text()) - float(IL_form.IL_Sweeping_form.txt_startwave.text())) / float(IL_form.IL_Sweeping_form.txt_wavestep.text()) + 1

            if datapoint != len(lstMonitor):
                QMessageBox.information(None, 'warning', 'Reference data mismatch.Please selecet right data.', QMessageBox.Ok)
                return
            
            refdata_strunct = STSDataStruct()
            refdata_strunct.MPMNumber = mpm_number
            refdata_strunct.SlotNumber = slot_number
            refdata_strunct.ChannelNumber = ch_number
            refdata_strunct.RangeNumber = 1
            refdata_strunct.SweepCount = 1
            
            errorcode = Cal_STS.Add_Ref_Rawdata(lstPower, lstMonitor, item)

            if errorcode != 0:
                Show_Inst_Error(errorcode)
                return
    else:
    
        for loop1 in range(1, int(ch_count) + 1):

            tempHeader = read_data.columns[loop1]

            chk_str = tempHeader[3:4]
            mpm_number = int(chk_str)
            
            chk_str = tempHeader[8:9]
            slot_number = int(chk_str)
    
            chk_str = tempHeader[11:12]
            ch_number = int(chk_str)
    
            for item in Data_struct:
    
                if item.MPMNumber == mpm_number and item.SlotNumber == slot_number and item.ChannelNumber == ch_number:
                    match_flag = True
                    break
    
            if match_flag == False:
                QMessageBox.information(None, 'warning', 'Reference data mismatch.Please selecet right data.', QMessageBox.Ok)
                return
            
            lstWave = read_data[read_data.columns[0]].to_list()
            if lstWave[len(lstWave) - 1] != float(IL_form.IL_Sweeping_form.txt_stopwave.text()):
                QMessageBox.information(None, 'warning', 'Reference data mismatch.Please selecet right data.', QMessageBox.Ok)
                return
    
            lstPower = read_data[tempHeader].to_list()
            tempMonitorHeader = read_data.columns[int(ch_count) + 1]
            lstMonitor = read_data[tempMonitorHeader].to_list()
            
            datapoint = (float(IL_form.IL_Sweeping_form.txt_stopwave.text()) - float(IL_form.IL_Sweeping_form.txt_startwave.text())) / float(IL_form.IL_Sweeping_form.txt_wavestep.text()) + 1
    
            if datapoint != len(lstMonitor):
                QMessageBox.information(None, 'warning', 'Reference data mismatch.Please selecet right data.', QMessageBox.Ok)
                return
            
            refdata_strunct = STSDataStruct()
            refdata_strunct.MPMNumber = mpm_number
            refdata_strunct.SlotNumber = slot_number
            refdata_strunct.ChannelNumber = ch_number
            refdata_strunct.RangeNumber = 1
            refdata_strunct.SweepCount = 1
            
            errorcode = Cal_STS.Add_Ref_Rawdata(lstPower, lstMonitor, item)
    
            if errorcode != 0:
                Show_Inst_Error(errorcode)
                return
    
    QMessageBox.information(None, 'information', 'Completed.', QMessageBox.Ok)

# initial TSL
def initial_tsl():
    tsl_information = {"Product: ": tsl_.Information.ProductName, "SN: ": tsl_.Information.SerialNumber,
                       "FW Ver: ": tsl_.Information.FWversion, "Wavelength range: ":
                           str(tsl_.Information.MinimunWavelength) + ' ~ ' + str(tsl_.Information.MaximumWavelength),
                       "Power range: ": str(tsl_.Information.MinimumAPCPower_dBm) + ' ~ ' + str(tsl_.Information.
                                                                                                MaximumAPCPower_dBm)}
    if tsl_.Information.ProductName == "TSL-570":
        error_code, sweep_table = tsl_.Get_Sweep_Speed_table([])
        if error_code != 0:
            show_instrument_error(error_code)
            return
    return tsl_information

# initial MPM
def initial_mpm():
    mpm_information = {"Product: ": mpm_.Information.ProductName, "FW Ver: ": mpm_.Information.FWversion,
                       "Module Type: ": mpm_.Information.ModuleType, "Enable module: ":
                           str(mpm_.Information.NumberofModule)}
    # Prepare ranges based on the module type
    for module_count in range(0, mpm_.Information.NumberofModule):
        if mpm_.Information.ModuleType[module_count] == "MPM-213":
            # MPM-213 doesn't have rage 5
            IL_form.chk_range5.setEnabled(False)
            MPM_213_flag = True
            break
        elif mpm_.Information.ModuleType[module_count] == "MPM-215":
            # MPM-215 only has range 1
            IL_form.chk_range1.setChecked(True)
            MPM_215_flag = True
            for range_number in range(2, 6):
                exec("IL_form.chk_range%d.setEnabled(False)" % range_number)
            break
        # Prepare channel based on the enabled module
        if mpm_.Information.ModuleType[module_count] == "MPM-212":
            # MPM-212 only has 2 channel
            exec("IL_form.chk_m1s%dc1.setEnabled(True)" % module_count)
            exec("IL_form.chk_m1s%dc2.setEnabled(True)" % module_count)
            # exec("IL_form.chk_m1s%dc3.setDisabled(True)" % module_count)
            # exec("IL_form.chk_m1s%dc4.setDisabled(True)" % module_count)
        else:
            exec("IL_form.chk_m1s%dc1.setEnabled(True)" % module_count)
            exec("IL_form.chk_m1s%dc2.setEnabled(True)" % module_count)
            exec("IL_form.chk_m1s%dc3.setEnabled(True)" % module_count)
            exec("IL_form.chk_m1s%dc4.setEnabled(True)" % module_count)
    return mpm_information

# disconnect instrument
def on_disconnect():
    tsl_.DisConnect()
    for mpm in mpms:
        mpm.DisConnect()
    spu_.DisConnect()
    IL_form.btn_connect.setDisabled(False)
    IL_form.btn_add_device.setDisabled(False)
    IL_form.btn_delete_device.setDisabled(False)
    
    if IL_form.IL_Sweeping_form != None:
        IL_form.IL_Sweeping_form.close()
    
# add mpm into listview
def on_add_device():
    # TSL GPIB communication
    if IL_form.rdo_mpm_gpib.isChecked():
        IL_form.list_widget_1.addItem(str(IL_form.txt_mpm_gpib_board.text()) + "::" + str(IL_form.txt_mpm_gpib_address.text()))
    else:
        IL_form.list_widget_1.addItem(str(IL_form.txt_mpm_ip.text()) + ":" + str(IL_form.txt_mpm_port.text()))
        
# delete mpm from listview
def on_del_device():
    IL_form.list_widget_1.takeItem(IL_form.list_widget_1.row(IL_form.list_widget_1.currentItem()))
    
# connect instrument and initial
def on_connect():
    
    global Flag_570
    
    # TSL GPIB communication
    if IL_form.rdo_tsl_gpib.isChecked():
        tsl_connect_type = CommunicationMethod.GPIB
        tsl_.GPIBConnectType = GPIBConnectType.NI4882
        tsl_.GPIBBoard = IL_form.txt_tsl_gpib_board.text()
        tsl_.GPIBAddress = str(IL_form.txt_tsl_gpib_address.text())
        tsl_.Terminator = CommunicationTerminator.CrLf
        # TSL TCP/IP communication
    if IL_form.rdo_tsl_tcpip.isChecked():
        tsl_connect_type = CommunicationMethod.TCPIP
        tsl_.IPAddress = str(IL_form.txt_tsl_ip.text())
        tsl_.Port = str(IL_form.txt_tsl_port.text())
        tsl_.Terminator = CommunicationTerminator.Cr
        # TSL USB communication
    if IL_form.rdo_tsl_usb.isChecked():
        tsl_connect_type = CommunicationMethod.USB
        tsl_.Terminator = CommunicationTerminator.Cr
        tsl_.DeviceID = IL_form.cmb_tsl_usb.currentIndex()

    error_code = tsl_.Connect(tsl_connect_type)
    if error_code != 0:
        show_instrument_error(error_code)
        return
    
    for i in range(IL_form.list_widget_1.count()):
        connectString = IL_form.list_widget_1.item(i).text()
        if connectString.find('::') > -1:
            connectStrs = connectString.split('::', 1)
            mpm = MPM()
            mpm.GPIBConnectType = GPIBConnectType.NI4882
            mpm.GPIBBoard = connectStrs[0]
            mpm.GPIBAddress = connectStrs[1]
            error_code = mpm.Connect(CommunicationMethod.GPIB)

            if error_code != 0:
                show_instrument_error(error_code)
                return
            mpms.append(mpm)
            
        elif connectString.find(':') > -1:
            connectStrs = connectString.split(':', 1)

            mpm = MPM()
            mpm.IPAddress = str(connectStrs[0])
            mpm.Port = connectStrs[1]
            error_code = mpm.Connect(CommunicationMethod.TCPIP)
            if error_code != 0:
                show_instrument_error(error_code)
                return
            mpms.append(mpm)

    # DAQ(SPU) communication
    spu_ID = IL_form.cmb_dev_number.currentText()
    spu_.DeviceName = spu_ID
    error_code, ans_ = spu_.Connect(' ')
    if error_code != 0:
        show_instrument_error(error_code)
        return
    
    if IL_form.rdo_tsl570.isChecked() == True:
        Flag_570 = True
    else:
        Flag_570 = False

    # インスツルメント初期化
    initial_tsl()
    #initial_mpm()
    
    error_code = Check_Module_Information()
    if error_code != 0:
        show_instrument_error(error_code)
        return
    
    Referect_EnableCh_for_form()
    Referect_EnableRange_for_form()
    error_code = Add_TSL_Sweep_Speed()
    if error_code != 0:
        QMessageBox.warning(None, 'Waring', "TSL Device is not TSL-570.", QMessageBox.Ok)
        on_disconnect()
        return
    
    # 全てのインスツルメント通信出来た場合、メッセージ出す
    QMessageBox.information(None, 'Information', 'All instrument was connected.', QMessageBox.Ok)
    IL_form.btn_connect.setDisabled(True)
    IL_form.btn_add_device.setDisabled(True)
    IL_form.btn_delete_device.setDisabled(True)
    
    IL_form.IL_Sweeping_form.setWindowTitle('IL STS Sample')
    IL_form.IL_Sweeping_form.setWindowIcon(QIcon(root + "./SANTEC.ico"))
    IL_form.IL_Sweeping_form.show()
    
    IL_form.IL_Sweeping_form.txt_wavestep.setText("0.01")
    IL_form.IL_Sweeping_form.txt_power.setText("10")
    if Flag_570 == False:
        IL_form.IL_Sweeping_form.txt_sweepspeed.setText("50")
    IL_form.IL_Sweeping_form.txt_startwave.setText(str(tsl_.Information.MinimunWavelength))
    IL_form.IL_Sweeping_form.txt_stopwave.setText(str(tsl_.Information.MaximumWavelength))
 
def Check_Module_Information():
    
    global Flag_215
    global Flag_213

    counter_215 = 0

    for mpm in mpms:
        for module in range(5):
            if mpm.Information.ModuleEnable[module] == True:

                if mpm.Information.ModuleType[module] == "MPM-215":
                    Flag_215 = True
                    counter_215 = counter_215 + 1

                if mpm.Information.ModuleType[module] == "MPM-213":
                    Flag_213 = True


    enable_module_count = 0
    
    for mpm in mpms:
        enable_module_count = mpm.Information.NumberofModule + enable_module_count 

    if Flag_215 == True:
        if enable_module_count != counter_215:
            return -1
    return 0

def Referect_EnableCh_for_form():

    mpm_index = 0
    for mpm in mpms:
        enable_slot = mpm.Information.ModuleEnable;
        mpm_index = mpm_index + 1

        for moduleIndex in range(5):
            if enable_slot[moduleIndex] == True:
                slot_type = mpm.Information.ModuleType[moduleIndex]
                if slot_type != "MPM-212":
                    box = QCheckBox(str(mpm_index) + "-" + str(moduleIndex) + "-1")
                    item = QListWidgetItem()
                    IL_form.IL_Sweeping_form.list_widget_channel.addItem(item)
                    IL_form.IL_Sweeping_form.list_widget_channel.setItemWidget(item, box)
                    
                    box1 = QCheckBox(str(mpm_index) + "-" + str(moduleIndex) + "-2")
                    item1 = QListWidgetItem()
                    IL_form.IL_Sweeping_form.list_widget_channel.addItem(item1)
                    IL_form.IL_Sweeping_form.list_widget_channel.setItemWidget(item1, box1)
                    
                    box2 = QCheckBox(str(mpm_index) + "-" + str(moduleIndex) + "-3")
                    item2 = QListWidgetItem()
                    IL_form.IL_Sweeping_form.list_widget_channel.addItem(item2)
                    IL_form.IL_Sweeping_form.list_widget_channel.setItemWidget(item2, box2)

                    box3 = QCheckBox(str(mpm_index) + "-" + str(moduleIndex) + "-4")
                    item3 = QListWidgetItem()
                    IL_form.IL_Sweeping_form.list_widget_channel.addItem(item3)
                    IL_form.IL_Sweeping_form.list_widget_channel.setItemWidget(item3, box3)
                else:
                    box = QCheckBox(str(mpm_index) + "-" + str(moduleIndex) + "-1")
                    item = QListWidgetItem()
                    IL_form.IL_Sweeping_form.list_widget_channel.addItem(item)
                    IL_form.IL_Sweeping_form.list_widget_channel.setItemWidget(item, box)
                    
                    box1 = QCheckBox(str(mpm_index) + "-" + str(moduleIndex) + "-2")
                    item1 = QListWidgetItem()
                    IL_form.IL_Sweeping_form.list_widget_channel.addItem(item1)
                    IL_form.IL_Sweeping_form.list_widget_channel.setItemWidget(item1, box1)
                    
def Referect_EnableRange_for_form():
    
    global Flag_213
    if Flag_213 == True:
        
        box = QCheckBox("Range1")
        item = QListWidgetItem()
        IL_form.IL_Sweeping_form.list_widget_range.addItem(item)
        IL_form.IL_Sweeping_form.list_widget_range.setItemWidget(item, box)

        box1 = QCheckBox("Range2")
        item1 = QListWidgetItem()
        IL_form.IL_Sweeping_form.list_widget_range.addItem(item1)
        IL_form.IL_Sweeping_form.list_widget_range.setItemWidget(item1, box1)
        
        box2 = QCheckBox("Range3")
        item2 = QListWidgetItem()
        IL_form.IL_Sweeping_form.list_widget_range.addItem(item2)
        IL_form.IL_Sweeping_form.list_widget_range.setItemWidget(item2, box2)
        
        box3 = QCheckBox("Range4")
        item3 = QListWidgetItem()
        IL_form.IL_Sweeping_form.list_widget_range.addItem(item3)
        IL_form.IL_Sweeping_form.list_widget_range.setItemWidget(item3, box3)

    else:

        box = QCheckBox("Range1")
        item = QListWidgetItem()
        IL_form.IL_Sweeping_form.list_widget_range.addItem(item)
        IL_form.IL_Sweeping_form.list_widget_range.setItemWidget(item, box)

        box1 = QCheckBox("Range2")
        item1 = QListWidgetItem()
        IL_form.IL_Sweeping_form.list_widget_range.addItem(item1)
        IL_form.IL_Sweeping_form.list_widget_range.setItemWidget(item1, box1)
        
        box2 = QCheckBox("Range3")
        item2 = QListWidgetItem()
        IL_form.IL_Sweeping_form.list_widget_range.addItem(item2)
        IL_form.IL_Sweeping_form.list_widget_range.setItemWidget(item2, box2)
        
        box3 = QCheckBox("Range4")
        item3 = QListWidgetItem()
        IL_form.IL_Sweeping_form.list_widget_range.addItem(item3)
        IL_form.IL_Sweeping_form.list_widget_range.setItemWidget(item3, box3)
        
        box4 = QCheckBox("Range5")
        item4 = QListWidgetItem()
        IL_form.IL_Sweeping_form.list_widget_range.addItem(item4)
        IL_form.IL_Sweeping_form.list_widget_range.setItemWidget(item4, box4)

    if Flag_215 == True:
        IL_form.IL_Sweeping_form.list_widget_range.setDisabled(True)

def Add_TSL_Sweep_Speed():
    
    global Flag_570

    if Flag_570 == True:
        sweep_table = []
        inst_error, sweep_table = tsl_.Get_Sweep_Speed_table(None)
    
        if inst_error != 0 & inst_error != ExceptionCode.DeviceError:
            return inst_error

    #if inst_error != ExceptionCode.DeviceError:
    #    for speed in sweep_table:
    #        this.cmbspeed.Items.Add(speed)
    
    if Flag_570 == True:
        IL_form.IL_Sweeping_form.txt_sweepspeed = QtWidgets.QComboBox(IL_form.IL_Sweeping_form.grb_sweep_setting)
        IL_form.IL_Sweeping_form.txt_sweepspeed.setGeometry(QtCore.QRect(400, 40, 113, 26))
        IL_form.IL_Sweeping_form.txt_sweepspeed.setTabletTracking(True)
        IL_form.IL_Sweeping_form.txt_sweepspeed.setObjectName("txt_sweepspeed")
        
        for speed in sweep_table:
            IL_form.IL_Sweeping_form.txt_sweepspeed.addItem(str(speed))
        
    else:
        IL_form.IL_Sweeping_form.txt_sweepspeed = QtWidgets.QLineEdit(IL_form.IL_Sweeping_form.grb_sweep_setting)
        IL_form.IL_Sweeping_form.txt_sweepspeed.setGeometry(QtCore.QRect(400, 40, 113, 26))
        IL_form.IL_Sweeping_form.txt_sweepspeed.setTabletTracking(True)
        IL_form.IL_Sweeping_form.txt_sweepspeed.setObjectName("txt_sweepspeed")
            
    return 0

# set parameter for measure
def set_parameterformeasure():
    
    startwave = float(IL_form.IL_Sweeping_form.txt_startwave.text())
    stopwave = float(IL_form.IL_Sweeping_form.txt_stopwave.text())
    wavestep = float(IL_form.IL_Sweeping_form.txt_wavestep.text())
    if Flag_570 == True:
        speed = float(IL_form.IL_Sweeping_form.txt_sweepspeed.currentText())
    else:
        speed = float(IL_form.IL_Sweeping_form.txt_sweepspeed.text())
    set_pow = float(IL_form.IL_Sweeping_form.txt_power.text())
    
    # ----TSL Setting 
    inst_error = tsl_.Set_APC_Power_dBm(set_pow)
    if inst_error != 0:
        Show_Inst_Error(inst_error)
        return

    inst_error = tsl_.TSL_Busy_Check(3000)
    if inst_error != 0:
        Show_Inst_Error(inst_error)
        return

    inst_error, tsl_acctualstep = tsl_.Set_Sweep_Parameter_for_STS(startwave, stopwave, speed, wavestep, -9999);

    if inst_error != 0:
        Show_Inst_Error(inst_error)
        return
    
    inst_error = tsl_.Set_Wavelength(startwave)
    if inst_error != 0:
        Show_Inst_Error(inst_error)
        return

    inst_error = tsl_.TSL_Busy_Check(3000)
    if inst_error != 0:
        Show_Inst_Error(inst_error)
        return
    
    for mpm in mpms:

        inst_error = mpm.Set_Logging_Paremeter_for_STS(startwave, stopwave, wavestep, speed, MPM.Measurement_Mode.Freerun)
        if inst_error != 0:
            Show_Inst_Error(inst_error)
            return

    inst_error, averaging_time = mpms[0].Get_Averaging_Time(-999);

    if inst_error != 0:
        Show_Inst_Error(inst_error)
        return
    
    inst_error = spu_.Set_Sampling_Parameter(startwave, stopwave, speed, tsl_acctualstep);

    if inst_error != 0:
        Show_Inst_Error(inst_error)
        return

    spu_.AveragingTime = averaging_time
    
    sts_error = Cal_STS.Clear_Measdata();

    if sts_error != 0:
        Show_STS_Error(sts_error)
        return

    sts_error = Cal_STS.Clear_Refdata()
    if sts_error != 0:
        Show_STS_Error(sts_error)
        return
    
    sts_error = Cal_STS.Set_Rescaling_Setting(RescalingMode.Freerun_SPU, averaging_time, True)
    if sts_error != 0:
        Show_STS_Error(sts_error)
        return

    sts_error = Cal_STS.Make_Sweep_Wavelength_Table(startwave, stopwave, tsl_acctualstep)
    if sts_error != 0:
        Show_STS_Error(sts_error)
        return
    
    sts_error = Cal_STS.Make_Target_Wavelength_Table(startwave, stopwave, wavestep)
    if sts_error != 0:
        Show_STS_Error(sts_error)
        return
    
    if IL_form.IL_Sweeping_form.chkeach_ch.isChecked():
        Prepare_dataST_Each()
    else:
        Prepare_dataST()

    if float(tsl_acctualstep) != wavestep:
        QMessageBox.warning(None, 'Waring', "Parameter set Success.\nThe acctual step set with " + str(tsl_acctualstep), QMessageBox.Ok)
    else:
        QMessageBox.warning(None, 'Waring', "Parameter set Success.", QMessageBox.Ok)

# sweep process
def sts_sweep_process():
    # MPM logging start
    error_code = mpm_.Logging_Start()
    if error_code != 0:
        show_instrument_error(error_code)
        return

    error_code = tsl_.Waiting_For_Sweep_Status(2000, tsl_.Sweep_Status.WaitingforTrigger)
    if error_code != 0:
        # When TSL fails, MPM stops logging
        mpm_.Logging_Stop()
        show_instrument_error(error_code)
        return

    error_code = spu_.Sampling_Start()
    if error_code != 0:
        mpm_.Logging_Stop()
        show_instrument_error(error_code)
        return

    error_code = tsl_.Set_Software_Trigger()
    if error_code != 0:
        mpm_.Logging_Stop()
        show_instrument_error(error_code)
        return

    error_code = spu_.Waiting_for_sampling()
    if error_code != 0:
        mpm_.Logging_Stop()
        tsl_.Sweep_Stop()
        show_instrument_error(error_code)
        return

    logging_status = 0
    logging_point = 0
    start_time = time.perf_counter()
    while logging_status == 0:
        error_code, logging_status, logging_point = mpm_.Get_Logging_Status(logging_status, logging_point)

        if error_code != 0:
            mpm_.Logging_Stop()
            show_instrument_error(error_code)
            return

        if logging_status == 1:
            break
        end_time = time.perf_counter()

        if end_time - start_time > 2000:
            mpm_.Logging_Stop()
            error_code = -9999
            break

    if error_code == -999:
        QMessageBox.warning(None, 'Waring', '"MPM Trigger receive error! Please check trigger cable connection.',
                            QMessageBox.Ok)
        return

    error_code = tsl_.Waiting_For_Sweep_Status(5000, tsl_.Sweep_Status.Standby)
    if error_code != 0:
        show_instrument_error(error_code)
        return
    return error_code

# STS reference
def reference():

    for mpm in mpms:

        inst_error = mpm.Set_Range(Meas_rang[0])
        if inst_error != 0:
            Show_Inst_Error(inst_error)
            return

    inst_error = tsl_.Sweep_Start()
    if inst_error != 0:
        Show_Inst_Error(inst_error)
        
    global inst_flag
        
    if IL_form.IL_Sweeping_form.chkeach_ch.isChecked():

        for item in Refdata_struct:
            
            QMessageBox.warning(None, 'Waring', 'Connect fiber to MPM' + str(item.MPMNumber) + '_Slot' + str(item.SlotNumber) + '_Ch' + str(item.ChannelNumber) + '.',
                                    QMessageBox.Ok)

            inst_error = Sweep_Process()
            if inst_error == -9999:
                QMessageBox.warning(None, 'Waring', 'MPM Trigger receive error! Please check trigger cable connection.',
                    QMessageBox.Ok)
                return 
            
            if inst_error != 0:
                Show_Inst_Error(inst_error)
                return

            inst_error = tsl_.Sweep_Start()
            if inst_error != 0:
                Show_Inst_Error(inst_error)

            inst_error = Get_Each_channel_reference_samplingdata(item.MPMNumber, item.SlotNumber, item.ChannelNumber, item.SweepCount)

            if inst_error != 0:
                if inst_flag == True:
                    Show_Inst_Error(inst_error)
                else:
                    Show_STS_Error(inst_error)

                return

            process_error = Cal_STS.Cal_RefData_Rescaling()

            if process_error != 0:
                Show_STS_Error(process_error)
                return

    else:
        inst_error = Sweep_Process()
        if inst_error == -9999:
    
            QMessageBox.warning(None, 'Waring', 'MPM Trigger receive error! Please check trigger cable connection.', QMessageBox.Ok)
            return
        
        if inst_error != 0:
            Show_Inst_Error(inst_error)
            return
    
        inst_error = tsl_.Sweep_Start()
        if inst_error != 0:
            Show_Inst_Error(inst_error)
    
        inst_error = Get_reference_samplingdata()
    
        if inst_error != 0:
            if inst_flag == True:
                Show_Inst_Error(inst_error)
            else:
                Show_STS_Error(inst_error)
            return
    
        process_error = Cal_STS.Cal_RefData_Rescaling()
    
        if process_error != 0:
            Show_STS_Error(process_error)
            return

    inst_error = tsl_.Sweep_Stop()
    if inst_error != 0:
        Show_Inst_Error(inst_error)
        return

    QMessageBox.warning(None, 'Waring', 'Completed.', QMessageBox.Ok)
    
    
def Sweep_Process():

    for mpm in mpms:
        inst_error = mpm.Logging_Start()
        if inst_error != 0:
            return inst_error

    inst_error = tsl_.Waiting_For_Sweep_Status(4000, TSL.Sweep_Status.WaitingforTrigger)

    if inst_error != 0:
        for mpm in mpms:
            mpm.Logging_Stop()
        return inst_error

    inst_error = spu_.Sampling_Start()
    if inst_error != 0:
        return inst_error

    inst_error = tsl_.Set_Software_Trigger()

    if inst_error != 0:
        for mpm in mpms:
            mpm.Logging_Stop()
        return inst_error

    inst_error = spu_.Waiting_for_sampling()

    if inst_error != 0:
        for mpm in mpms:
            mpm.Logging_Stop()
        return inst_error

    mpm_stauts = 0
    mpm_count = 0       
    mpm_completed_falg = True                 
    isSweeping = True

    first_time = time.time() * 1000
    while isSweeping:
        for mpm in mpms:

            inst_error, mpm_stauts, mpm_count = mpm.Get_Logging_Status(mpm_stauts, mpm_count)
            if inst_error != 0:
                return inst_error
            if mpm_stauts == 1:
                isSweeping = False
                break
            
            second_time = time.time() * 1000
            if (second_time - first_time) >= 2000:

                mpm_completed_falg = False
                isSweeping = False
                break

    for mpm in mpms:
        inst_error = mpm.Logging_Stop()
        if inst_error != 0:
            return inst_error

    inst_error = tsl_.Waiting_For_Sweep_Status(5000, tsl_.Sweep_Status.Standby)

    if inst_error != 0:
        return inst_error

    if mpm_completed_falg == False:
        return -9999

    return 0

def Get_reference_samplingdata():
    
    global Ref_monitor_struct
    global inst_flag

    global mpmLoggData

    for item in Refdata_struct:

        inst_error = Get_MPM_Loggdata(item.MPMNumber, item.SlotNumber, item.ChannelNumber)

        if inst_error != 0:
            inst_flag = True
            return inst_error

        logg_data = mpmLoggData  

        cal_error = Cal_STS.Add_Ref_MPMData_CH(logg_data, item)

        if cal_error != 0:
            inst_flag = False
            return cal_error

    inst_error, triggerdata, monitordata = spu_.Get_Sampling_Rawdata(None, None)

    if inst_error != 0:
        inst_flag = True
        return inst_error

    for monitor_item in Ref_monitordata_struct:

        cal_error = Cal_STS.Add_Ref_MonitorData(triggerdata, monitordata, monitor_item)
        if cal_error != 0:
            inst_flag = False
            return cal_error

    return 0

def Get_Each_channel_reference_samplingdata(currentMPMNumber, currentSlotNumber, currentChannelNumber, currentSweepCount):

    for item in Refdata_struct:

        if item.MPMNumber != currentMPMNumber or item.SlotNumber != currentSlotNumber or item.ChannelNumber != currentChannelNumber:
            continue

        inst_error = Get_MPM_Loggdata(item.MPMNumber, item.SlotNumber, item.ChannelNumber)

        if inst_error != 0:
            inst_flag = True
            return inst_error
        
        logg_data = mpmLoggData

        cal_error = Cal_STS.Add_Ref_MPMData_CH(logg_data, item)

        if cal_error != 0:
            inst_flag = False
            return cal_error

    inst_error, triggerdata, monitordata = spu_.Get_Sampling_Rawdata(None, None)

    if inst_error != 0:
        inst_flag = True
        return inst_error

    for monitor_item in Ref_monitordata_struct:

        cal_error = Cal_STS.Add_Ref_MonitorData(triggerdata, monitordata, monitor_item)
        if cal_error != 0:
            inst_flag = False
            return cal_error

    return 0

def Get_MPM_Loggdata(deveice, slot, ch):

    global mpmLoggData
    inst_error, mpmLoggData = mpms[deveice].Get_Each_Channel_Logdata(slot, ch, None)
    return inst_error

# Measure process
def measure():

    inst_error = tsl_.Sweep_Start()
    if inst_error != 0:
        Show_Inst_Error(inst_error)
        return

    for loop1 in range(len(Meas_rang)):
        for mpm in mpms:
            inst_error = mpm.Set_Range(Meas_rang[loop1])

            if inst_error != 0:
                Show_Inst_Error(inst_error)
                return

        inst_error = Sweep_Process()
        if inst_error != 0:
            Show_Inst_Error(inst_error)
            return
        
        inst_error = tsl_.Sweep_Start()
        if inst_error != 0:
            Show_Inst_Error(inst_error)
            return

        inst_error = Get_measurement_samplingdata(loop1 + 1)

        if inst_error != 0:
            if inst_flag == True:
                Show_Inst_Error(inst_error)
            else:
                Show_STS_Error(inst_error)
            return

    process_error = Cal_STS.Cal_MeasData_Rescaling()

    if process_error != 0:
        Show_STS_Error(process_error)
        return

    if Flag_215 == False:

        if Flag_213 == True:
            merge_type = Module_Type.MPM_213
        else:
            merge_type = Module_Type.MPM_211

        process_error = Cal_STS.Cal_IL_Merge(merge_type)

    else:
        process_error = Cal_STS.Cal_IL()

    process_error = Save_Measurement_data()
    
    if process_error != 0:
        Show_STS_Error(process_error)

    inst_error = tsl_.Sweep_Stop()
    if inst_error != 0:
        Show_Inst_Error(inst_error)
        return

    QMessageBox.warning(None, 'Waring', 'Completed.', QMessageBox.Ok)
    
def Save_Measurement_data():

    lstILdata = []
    process_error, wavelength_table = Cal_STS.Get_Target_Wavelength_Table(None);

    global Data_struct
    global Mergedata_struct
    if Flag_215 == True:
        for items in Data_struct:
            process_error, ildata = Cal_STS.Get_IL_Data(None, items)
            if process_error != 0:
                return process_error

            lstILdata.append(ildata)
    else:
        for items in Mergedata_struct:
            process_error, ildata = Cal_STS.Get_IL_Merge_Data(None, items)
            if process_error != 0:
                return process_error

            lstILdata.append(ildata)
            
    title = []
    title.append("wavelength")
    
    for loop2 in range(len(lstILdata)):
        item = Data_struct[loop2]
        title.append("MPM" + str(item.MPMNumber) + "Slot" + str(item.SlotNumber) + "Ch" + str(item.ChannelNumber))
    
    result1 = []
    for loop1 in range(len(wavelength_table)):
        data = []
        for loop2 in range(len(lstILdata)):
            if loop2 == 0:
                data.append(wavelength_table[loop1])
            item = lstILdata[loop2]
            data.append(item[loop1])
        result1.append(data)

    file_path = save_function()
    cal_result = pd.DataFrame(result1, columns=title)
    cal_result.to_csv(file_path, index=False)

    return 0

def Get_measurement_samplingdata(sweepcount):
 
    global Data_struct
    global Meas_monitor_struct
    global inst_flag
    
    for item in Data_struct:

        if item.SweepCount != sweepcount:
            continue

        inst_error = Get_MPM_Loggdata(item.MPMNumber, item.SlotNumber, item.ChannelNumber)

        if inst_error != 0:
            inst_flag = True
            return inst_error

        logg_data = mpmLoggData

        cal_error = Cal_STS.Add_Meas_MPMData_CH(logg_data, item)

        if cal_error != 0:
            inst_flag = False
            return cal_error

    inst_error, triggerdata, monitordata = spu_.Get_Sampling_Rawdata(None, None)

    if inst_error != 0:
        inst_flag = True
        return inst_error

    for item in Meas_monitor_struct:
        if item.SweepCount == sweepcount:
            cal_error = Cal_STS.Add_Meas_MonitorData(triggerdata, monitordata, item)

            if cal_error != 0:
                inst_flag = False
                return cal_error
            break

    return 0

# Save data function
def save_function():
    options = QFileDialog.Options()
    options |= QFileDialog.DontUseNativeDialog
    file_path, filetype = QFileDialog.getSaveFileName(None, "Save data", "", "*.csv", options=options)
    if file_path.find('.csv') < 0:
        file_path = file_path + ".csv"
        
    return file_path

def Show_Inst_Error(errordata):
    QMessageBox.warning(None, 'Waring', errorInfo.get(errordata), QMessageBox.Ok)

def Prepare_dataST():
    
    global Ref_monitor_struct

    global Meas_rang
    global Data_struct
    global Refdata_struct
    global Meas_monitor_struct
    global Mergedata_struct
    global Ref_monitordata_struct

    Meas_rang.clear()
    Data_struct.clear()
    Refdata_struct.clear()
    Ref_monitordata_struct.clear()
    Meas_monitor_struct.clear()
    Mergedata_struct.clear()

    allRangeCount = IL_form.IL_Sweeping_form.list_widget_range.count()
    allRangeList = [IL_form.IL_Sweeping_form.list_widget_range.itemWidget(IL_form.IL_Sweeping_form.list_widget_range.item(i))
                for i in range(allRangeCount)]
    
    checkedRanges = []
    for range1 in allRangeList:
        if range1.isChecked():
            checkedRanges.append(range1.text())
            
    rangecout = checkedRanges.count
    
    allChannelCount = IL_form.IL_Sweeping_form.list_widget_channel.count()
    allChannelList = [IL_form.IL_Sweeping_form.list_widget_channel.itemWidget(IL_form.IL_Sweeping_form.list_widget_channel.item(i))
                    for i in range(allChannelCount)]
    
    global checkedChannels
    checkedChannels = []
    for channel in allChannelList:
        if channel.isChecked():
            checkedChannels.append(channel.text())
            
    chcount = checkedChannels.count

    if Flag_215 == True:
        Meas_rang.append(1)
    else:
        if rangecout == 0 or chcount == 0:
            QMessageBox.warning(None, 'Information', "Please check measurement parameters.", QMessageBox.Ok)
            return

        for checkedRange in checkedRanges:
            Meas_rang.append(int(checkedRange.replace("Range","")))

    for loop2 in range(len(Meas_rang)):
        for checkChannel in checkedChannels:

            text_st = checkChannel
            split_st = text_st.split("-")
            
            device_number = int(split_st[0]) - 1
            slot_number = int(split_st[1])
            ch_number = int(split_st[2])
            set_struct = STSDataStruct()
            set_struct.MPMNumber = device_number
            set_struct.SlotNumber = slot_number
            set_struct.ChannelNumber = ch_number
            set_struct.RangeNumber = Meas_rang[loop2]
            set_struct.SweepCount = loop2 + 1
            set_struct.SOP = 0
            Data_struct.append(set_struct)

    for loop2 in range(len(Meas_rang)):
        for checkChannel in checkedChannels:

            text_st = checkChannel
            split_st = text_st.split("-")
            
            device_number = int(split_st[0]) - 1

            set_monitor_struct = STSMonitorStruct()
            set_monitor_struct.MPMNumber = device_number
            set_monitor_struct.SOP = 0
            set_monitor_struct.SweepCount = loop2 + 1

            Meas_monitor_struct.append(set_monitor_struct)
            if len(Meas_monitor_struct) == loop2 + 1:
                break

    for checkChannel in checkedChannels:

        text_st = checkChannel
        split_st = text_st.split("-")

        device_number = int(split_st[0]) - 1
        slot_numbe = int(split_st[1])
        ch_number = int(split_st[2])

        set_struct = STSDataStruct()
        set_struct.MPMNumber = device_number
        set_struct.SlotNumber = slot_number
        set_struct.ChannelNumber = ch_number
        set_struct.RangeNumber = 1
        set_struct.SweepCount = 1
        set_struct.SOP = 0

        Refdata_struct.append(set_struct)

        set_struct_merge = STSDataStructForMerge()
        set_struct_merge.MPMNumber = device_number
        set_struct_merge.SlotNumber = slot_number
        set_struct_merge.ChannelNumber = ch_number
        set_struct_merge.SOP = 0
        Mergedata_struct.append(set_struct_merge)

    for checkChannel in checkedChannels:

        text_st = checkChannel
        split_st = text_st.split("-")
        device_number = int(split_st[0]) - 1
        slot_numbe = int(split_st[1])
        ch_number = int(split_st[2])

        set_ref_monitor_struct = STSDataStruct()

        set_ref_monitor_struct.MPMNumber = device_number
        set_ref_monitor_struct.SlotNumber = slot_number
        set_ref_monitor_struct.ChannelNumber = ch_number
        set_ref_monitor_struct.RangeNumber = 1
        set_ref_monitor_struct.SOP = 0
        set_ref_monitor_struct.SweepCount = 1

        Ref_monitordata_struct.append(set_ref_monitor_struct)
        break

def Prepare_dataST_Each():

    rangecout = 0
    chcount = 0
    loop1 = 0
    loop2 = 0
    text_st = "" 
    split_st = []

    global Meas_rang
    global Data_struct
    global Refdata_struct
    global Ref_monitordata_struct
    global Meas_monitor_struct
    global Mergedata_struct
    
    Meas_rang.clear()
    Data_struct.clear() 
    Refdata_struct.clear()
    Ref_monitordata_struct.clear()
    Meas_monitor_struct.clear()

    Mergedata_struct.clear()
    
    allRangeCount = IL_form.IL_Sweeping_form.list_widget_range.count()
    allRangeList = [IL_form.IL_Sweeping_form.list_widget_range.itemWidget(IL_form.IL_Sweeping_form.list_widget_range.item(i))
                for i in range(allRangeCount)]
    
    checkedRanges = []
    for range1 in allRangeList:
        if range1.isChecked():
            checkedRanges.append(range1.text())
            
    rangecout = checkedRanges.count
    
    allChannelCount = IL_form.IL_Sweeping_form.list_widget_channel.count()
    allChannelList = [IL_form.IL_Sweeping_form.list_widget_channel.itemWidget(IL_form.IL_Sweeping_form.list_widget_channel.item(i))
                    for i in range(allChannelCount)]
    
    global checkedChannels
    checkedChannels = []
    for channel in allChannelList:
        if channel.isChecked():
            checkedChannels.append(channel.text())
            
    chcount = checkedChannels.count

    global Flag_215
    
    if Flag_215 == True:
        Meas_rang.append(1)
    else:
        if rangecout == 0 or chcount == 0:
            QMessageBox.warning(None, 'Waring', "Please check measurement parameters.", QMessageBox.Ok)
            return

        for range1 in checkedRanges:
            Meas_rang.append(int(range1.replace("Range","")))

    for loop2 in range(len(Meas_rang)):
        for channel in checkedChannels:

            text_st = channel
            split_st = text_st.split("-")

            device_number = int(split_st[0])
            slot_number = int(split_st[1])
            ch_number = int(split_st[2])

            set_struct = STSDataStruct()
            set_struct.MPMNumber = device_number - 1
            set_struct.SlotNumber = slot_number
            set_struct.ChannelNumber = ch_number
            set_struct.RangeNumber = Meas_rang[loop2]
            set_struct.SweepCount = loop2 + 1
            set_struct.SOP = 0
            Data_struct.append(set_struct)

    for loop2 in range(len(Meas_rang)):
        for channel in checkedChannels:

            text_st = channel
            split_st = text_st.split("-")

            device_number = int(split_st[0])

            set_monitor_struct = STSMonitorStruct() 
            set_monitor_struct.MPMNumber = device_number - 1
            set_monitor_struct.SOP = 0
            set_monitor_struct.SweepCount = loop2 + 1

            Meas_monitor_struct.append(set_monitor_struct)
            if len(Meas_monitor_struct) == loop2 + 1:
                break

    for channel in checkedChannels:

        text_st = channel
        split_st = text_st.split("-")

        device_number = int(split_st[0])
        slot_number = int(split_st[1])
        ch_number = int(split_st[2])

        set_struct = STSDataStruct()

        set_struct.MPMNumber = device_number - 1
        set_struct.SlotNumber = slot_number
        set_struct.ChannelNumber = ch_number
        set_struct.RangeNumber = 1
        set_struct.SweepCount = 1
        set_struct.SOP = 0

        Refdata_struct.append(set_struct)

        set_ref_monitor_struct = STSDataStruct()

        set_ref_monitor_struct.MPMNumber = device_number - 1
        set_ref_monitor_struct.SlotNumber = slot_number
        set_ref_monitor_struct.ChannelNumber = ch_number
        set_ref_monitor_struct.RangeNumber = 1
        set_ref_monitor_struct.SweepCount = 1
        set_ref_monitor_struct.SOP = 0

        Ref_monitordata_struct.append(set_ref_monitor_struct)

        set_struct_merge = STSDataStructForMerge()
        set_struct_merge.MPMNumber = device_number - 1
        set_struct_merge.SlotNumber = slot_number
        set_struct_merge.ChannelNumber = ch_number
        set_struct_merge.SOP = 0
        Mergedata_struct.append(set_struct_merge)

if __name__ == "__main__":

    app = QtWidgets.QApplication(sys.argv)
    IL_form = IL_Window()
    IL_form.setWindowTitle('IL STS Sample')
    root = QFileInfo(__file__).absolutePath()
    IL_form.setWindowIcon(QIcon(root + "./SANTEC.ico"))
    app.setStyle('Fusion')
    IL_form.IL_Sweeping_form = IL_Sweeping_Window()
    IL_form.show()
    get_daq_id()
    get_pcu_usb_resource()
    get_tsl_usb_resource()
    sys.exit(app.exec_())

