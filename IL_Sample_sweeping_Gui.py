# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'PDL_Sample_Gui.ui'
#
# Created by: PyQt5 UI code generator 5.9.2
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_IL_Sweeping_Sample(object):
    def setupUi(self, IL_Sweeping_Sample):
        IL_Sweeping_Sample.setObjectName("IL_Sweeping_Sample")
        IL_Sweeping_Sample.resize(729, 320)
        IL_Sweeping_Sample.setMinimumSize(QtCore.QSize(729, 320))
        IL_Sweeping_Sample.setMaximumSize(QtCore.QSize(729, 320))
        IL_Sweeping_Sample.setFocusPolicy(QtCore.Qt.TabFocus)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("../../../../.designer/SANTEC.ICO"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        IL_Sweeping_Sample.setWindowIcon(icon)
        self.grb_sweep_setting = QtWidgets.QGroupBox(IL_Sweeping_Sample)
        self.grb_sweep_setting.setEnabled(True)
        self.grb_sweep_setting.setGeometry(QtCore.QRect(10, 10, 701, 81))
        self.grb_sweep_setting.setObjectName("grb_sweep_setting")
        self.label_12 = QtWidgets.QLabel(self.grb_sweep_setting)
        self.label_12.setGeometry(QtCore.QRect(10, 20, 121, 16))
        self.label_12.setObjectName("label_12")
        self.txt_startwave = QtWidgets.QLineEdit(self.grb_sweep_setting)
        self.txt_startwave.setGeometry(QtCore.QRect(10, 40, 113, 26))
        self.txt_startwave.setTabletTracking(True)
        self.txt_startwave.setObjectName("txt_startwave")
        self.label_13 = QtWidgets.QLabel(self.grb_sweep_setting)
        self.label_13.setGeometry(QtCore.QRect(140, 20, 121, 16))
        self.label_13.setObjectName("label_13")
        self.txt_stopwave = QtWidgets.QLineEdit(self.grb_sweep_setting)
        self.txt_stopwave.setGeometry(QtCore.QRect(140, 40, 113, 26))
        self.txt_stopwave.setTabletTracking(True)
        self.txt_stopwave.setObjectName("txt_stopwave")
        self.txt_wavestep = QtWidgets.QLineEdit(self.grb_sweep_setting)
        self.txt_wavestep.setGeometry(QtCore.QRect(270, 40, 113, 26))
        self.txt_wavestep.setTabletTracking(True)
        self.txt_wavestep.setObjectName("txt_wavestep")
        self.label_14 = QtWidgets.QLabel(self.grb_sweep_setting)
        self.label_14.setGeometry(QtCore.QRect(270, 20, 121, 16))
        self.label_14.setObjectName("label_14")
        self.txt_power = QtWidgets.QLineEdit(self.grb_sweep_setting)
        self.txt_power.setGeometry(QtCore.QRect(530, 40, 113, 26))
        self.txt_power.setTabletTracking(True)
        self.txt_power.setObjectName("txt_power")
        self.label_15 = QtWidgets.QLabel(self.grb_sweep_setting)
        self.label_15.setGeometry(QtCore.QRect(400, 20, 121, 16))
        self.label_15.setObjectName("label_15")
        self.label_16 = QtWidgets.QLabel(self.grb_sweep_setting)
        self.label_16.setGeometry(QtCore.QRect(530, 20, 121, 16))
        self.label_16.setObjectName("label_16")


        self.grb_measurement_set = QtWidgets.QGroupBox(IL_Sweeping_Sample)
        self.grb_measurement_set.setEnabled(True)
        self.grb_measurement_set.setGeometry(QtCore.QRect(10, 110, 701, 131))
        self.grb_measurement_set.setObjectName("grb_measurement_set")
        self.groupBox_11 = QtWidgets.QGroupBox(self.grb_measurement_set)
        self.groupBox_11.setEnabled(True)
        self.groupBox_11.setGeometry(QtCore.QRect(10, 20, 221, 101))
        self.groupBox_11.setObjectName("groupBox_11")
        
        self.list_widget_channel = QtWidgets.QListWidget(self.groupBox_11)
        self.list_widget_channel.setGeometry(QtCore.QRect(10, 30, 200, 60))
        self.list_widget_channel.setObjectName("list_widget_channel")
        
        self.groupBox_13 = QtWidgets.QGroupBox(self.grb_measurement_set)
        self.groupBox_13.setGeometry(QtCore.QRect(250, 20, 121, 101))
        self.groupBox_13.setObjectName("groupBox_13")
        
        self.list_widget_range = QtWidgets.QListWidget(self.groupBox_13)
        self.list_widget_range.setGeometry(QtCore.QRect(10, 30, 100, 60))
        self.list_widget_range.setObjectName("list_widget_range")


        self.btn_Set = QtWidgets.QPushButton(self.grb_measurement_set)
        self.btn_Set.setGeometry(QtCore.QRect(570, 90, 111, 31))
        self.btn_Set.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.btn_Set.setObjectName("btn_Set")
        self.btn_saverefrawdata = QtWidgets.QPushButton(IL_Sweeping_Sample)
        self.btn_saverefrawdata.setGeometry(QtCore.QRect(250, 260, 151, 31))
        self.btn_saverefrawdata.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.btn_saverefrawdata.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.btn_saverefrawdata.setAutoFillBackground(False)
        self.btn_saverefrawdata.setAutoRepeat(False)
        self.btn_saverefrawdata.setAutoExclusive(False)
        self.btn_saverefrawdata.setObjectName("btn_saverefrawdata")
        self.btn_readrefrawdata = QtWidgets.QPushButton(IL_Sweeping_Sample)
        self.btn_readrefrawdata.setGeometry(QtCore.QRect(420, 260, 151, 31))
        self.btn_readrefrawdata.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.btn_readrefrawdata.setObjectName("btn_readrefrawdata")
        self.btn_saverawdata = QtWidgets.QPushButton(IL_Sweeping_Sample)
        self.btn_saverawdata.setGeometry(QtCore.QRect(590, 260, 101, 31))
        self.btn_saverawdata.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.btn_saverawdata.setObjectName("btn_saverawdata")
        self.btn_reference = QtWidgets.QPushButton(IL_Sweeping_Sample)
        self.btn_reference.setGeometry(QtCore.QRect(10, 260, 101, 31))
        self.btn_reference.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.btn_reference.setObjectName("btn_reference")
        self.chkeach_ch = QtWidgets.QCheckBox(self.grb_measurement_set)
        self.chkeach_ch.setEnabled(True)
        self.chkeach_ch.setGeometry(QtCore.QRect(400, 90, 141, 31))
        self.chkeach_ch.setObjectName("chkeach_ch")
        self.btn_measurement = QtWidgets.QPushButton(IL_Sweeping_Sample)
        self.btn_measurement.setGeometry(QtCore.QRect(130, 260, 101, 31))
        self.btn_measurement.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.btn_measurement.setObjectName("btn_measurement")

        self.retranslateUi(IL_Sweeping_Sample)

        QtCore.QMetaObject.connectSlotsByName(IL_Sweeping_Sample)

    def retranslateUi(self, IL_Sweeping_Sample):
        _translate = QtCore.QCoreApplication.translate
        IL_Sweeping_Sample.setWindowTitle(_translate("IL_Sweeping_Sample", "Santec IL STS Sample"))

        self.grb_sweep_setting.setTitle(_translate("IL_Sweeping_Sample", "Sweep setting"))
        self.label_12.setText(_translate("IL_Sweeping_Sample", "Start wavelength(nm)"))
        self.label_13.setText(_translate("IL_Sweeping_Sample", "Stop wavelength(nm)"))
        self.label_14.setText(_translate("IL_Sweeping_Sample", "Wavelength step(nm)"))
        self.label_15.setText(_translate("IL_Sweeping_Sample", "Sweep speed(nm/s)"))
        self.label_16.setText(_translate("IL_Sweeping_Sample", "TSL power(dBm)"))
        self.grb_measurement_set.setTitle(_translate("IL_Sweeping_Sample", "Measurement CH And Range"))
        self.groupBox_11.setTitle(_translate("IL_Sweeping_Sample", "Channel"))
        self.groupBox_13.setTitle(_translate("IL_Sweeping_Sample", "Range"))

        self.chkeach_ch.setText(_translate("IL_Sweeping_Sample", "Each channel individually"))
        self.btn_Set.setText(_translate("IL_Sweeping_Sample", "Set"))
        self.btn_saverefrawdata.setText(_translate("IL_Sweeping_Sample", "Save reference raw data"))
        self.btn_readrefrawdata.setText(_translate("IL_Sweeping_Sample", "Read reference raw data"))
        self.btn_saverawdata.setText(_translate("IL_Sweeping_Sample", "Save raw data"))
        self.btn_reference.setText(_translate("IL_Sweeping_Sample", "Reference"))
        self.btn_measurement.setText(_translate("IL_Sweeping_Sample", "Measurement"))

