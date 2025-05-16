# -*- coding: utf-8 -*-
from burp import ITab, IBurpExtenderCallbacks
from javax.swing import (JPanel, JCheckBox, JScrollPane, JSplitPane,
                         BorderFactory, JTable, BoxLayout, JEditorPane,
                         JTabbedPane, JOptionPane, Box, JSeparator, JLabel,
                         SwingUtilities, JTextField, JFileChooser, JButton)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, FlowLayout, Font, Color
from java.awt.event import MouseAdapter, ItemListener, ItemEvent, FocusAdapter, FocusEvent
from javax.swing.event import HyperlinkEvent, HyperlinkListener
from java.net import URI
from java.awt import Desktop

from threading import Thread
import os
import time
import shutil

SETTING_PREFIX = "trufflehog_tool_"

class NonEditableTableModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False

class TruffleTab(ITab):
    SETTING_TRUFFLEHOG_PATH = "trufflehog_exec_path"

    def __init__(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.extender = None
        self.secrets_data = {}
        self.is_reloading = False
        self.unread_secrets = set()

        self.TOOL_FLAGS = {
            IBurpExtenderCallbacks.TOOL_PROXY:    {'name': 'Proxy',    'active': True},
            IBurpExtenderCallbacks.TOOL_SPIDER:   {'name': 'Spider',   'active': False},
            IBurpExtenderCallbacks.TOOL_SCANNER:  {'name': 'Scanner',  'active': False},
            IBurpExtenderCallbacks.TOOL_REPEATER: {'name': 'Repeater', 'active': False},
            IBurpExtenderCallbacks.TOOL_INTRUDER: {'name': 'Intruder', 'active': False},
            IBurpExtenderCallbacks.TOOL_SEQUENCER:{'name': 'Sequencer','active': False},
            IBurpExtenderCallbacks.TOOL_EXTENDER: {'name': 'Extender', 'active': False}
        }
        self.load_enabled_tools()

        self.TOOL_ORDER = [
            IBurpExtenderCallbacks.TOOL_PROXY,
            IBurpExtenderCallbacks.TOOL_INTRUDER,
            IBurpExtenderCallbacks.TOOL_REPEATER,
            IBurpExtenderCallbacks.TOOL_SEQUENCER,
            IBurpExtenderCallbacks.TOOL_SPIDER,
            IBurpExtenderCallbacks.TOOL_SCANNER,
            IBurpExtenderCallbacks.TOOL_EXTENDER
        ]

        stored_path = self._callbacks.loadExtensionSetting(self.SETTING_TRUFFLEHOG_PATH)
        if stored_path and os.path.isabs(stored_path):
            self.trufflehog_exec_path = stored_path
        else:
            self.trufflehog_exec_path = self.run_which("trufflehog")
            self._callbacks.saveExtensionSetting(self.SETTING_TRUFFLEHOG_PATH, self.trufflehog_exec_path)
            if not self.trufflehog_exec_path:
                self._callbacks.printOutput(
                    "TruffleHog binary not found in PATH. Set it manually in TruffleHog tab configuration."
                )

        self.panel = JPanel(BorderLayout())
        topPanel = self.createTopPanel()
        topScrollPane = JScrollPane(topPanel)
        topScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        topScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        self.panel.add(topScrollPane, BorderLayout.NORTH)

        mainSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        mainSplit.setResizeWeight(0.5)

        leftSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        leftSplit.setResizeWeight(0.5)
        leftSplit.setDividerLocation(200)

        self.secretModel = NonEditableTableModel(["Secret Type", "Redacted Secret", "Raw Secret"], 0)
        self.secretTable = JTable(self.secretModel)
        self.initSecretTable()
        secretsScrollPane = JScrollPane(self.secretTable)

        self.urlModel = NonEditableTableModel(["Location URLs"], 0)
        self.urlTable = JTable(self.urlModel)
        self.urlTable.setAutoCreateRowSorter(True)
        self.urlTable.addMouseListener(URLSelectionListener(self))
        urlsScrollPane = JScrollPane(self.urlTable)

        leftSplit.setTopComponent(secretsScrollPane)
        leftSplit.setBottomComponent(urlsScrollPane)

        self.tabs = JTabbedPane()

        self.advisoryPane = JEditorPane("text/html", "<html><body>Select a URL to see advisory</p></body></html>")
        self.advisoryPane.setEditable(False)
        advisoryScroll = JScrollPane(self.advisoryPane)
        self.tabs.addTab("Secret Details", advisoryScroll)

        self.requestViewer = self._callbacks.createMessageEditor(None, False)
        self.responseViewer = self._callbacks.createMessageEditor(None, False)
        self.tabs.addTab("Request", self.requestViewer.getComponent())
        self.tabs.addTab("Response", self.responseViewer.getComponent())

        mainSplit.setLeftComponent(leftSplit)
        mainSplit.setRightComponent(self.tabs)
        self.panel.add(mainSplit, BorderLayout.CENTER)

    def createTopPanel(self):
        infoLabel = JEditorPane(
            "text/html",
            "<html><body>"
            "<h1 style='margin-bottom:0;'>TruffleHog</h1> <img src='https://i.ibb.co/bmxd7Dh/th-pig-sm.png'>"
            "<p style='font-size:10px; padding-bottom:10px'>TruffleHog identifies over 800 different types of leaked credentials.<br>"
            "View the open-source code here: <a href='https://github.com/trufflesecurity/trufflehog'>https://github.com/trufflesecurity/trufflehog</a></p>"
            "</body></html>"
        )
        infoLabel.setEditable(False)
        infoLabel.setOpaque(False)
        infoLabel.addHyperlinkListener(LinkOpener())

        topPanel = JPanel()
        topPanel.setLayout(BoxLayout(topPanel, BoxLayout.Y_AXIS))
        topPanel.add(infoLabel)
        topPanel.add(JSeparator())

        infoLabel2H2 = JEditorPane("text/html", "<h2 style='margin-bottom:0; padding-bottom:0px'>Configuration Options</h2>")
        infoLabel2H2.setEditable(False)
        infoLabel2H2.setOpaque(False)
        topPanel.add(infoLabel2H2)

        configsPanel = JPanel()
        configsPanel.setLayout(BoxLayout(configsPanel, BoxLayout.X_AXIS))
        configsPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0))

        truffleConfigPanel = JPanel()
        truffleConfigPanel.setLayout(BoxLayout(truffleConfigPanel, BoxLayout.Y_AXIS))
        infoLabel2 = JEditorPane(
            "text/html",
            "<h3 style='margin-bottom:0; padding-top: 0px'>TruffleHog Configurations</h3>"
            "<p style='font-size:9px; margin-top: 0px; padding-top: 0px'>Customize whether TruffleHog "
            "<a href='https://trufflesecurity.com/blog/how-trufflehog-verifies-secrets'>verifies secrets</a>, "
            "and does <a href='https://trufflesecurity.com/blog/contributor-spotlight-helena-rosenzweig-and-assetnote-team#:~:text=Imagine%20two%20companies,allow%2Dverification%2Doverlap.'>"
            "overlapping secret checks.</a><br></p>"
        )
        infoLabel2.setEditable(False)
        infoLabel2.setOpaque(False)
        infoLabel2.addHyperlinkListener(LinkOpener())
        truffleConfigPanel.add(infoLabel2)

        truffleButtonsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.verifySecretsCheckbox = JCheckBox("Verify Secrets (--only-verified)", True)
        self.overlappingVerificationCheckbox = JCheckBox("Allow Overlapping Verification (--allow-verification-overlap)", False)
        checkbox_listener = CheckboxChangeListener(self)
        self.verifySecretsCheckbox.addItemListener(checkbox_listener)
        self.overlappingVerificationCheckbox.addItemListener(checkbox_listener)
        truffleButtonsPanel.add(self.verifySecretsCheckbox)
        truffleButtonsPanel.add(self.overlappingVerificationCheckbox)
        truffleConfigPanel.add(truffleButtonsPanel)

        # Bottom row: path to TruffleHog using a text field and a Browse button.
        pathFieldPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        pathLabel = JLabel("TruffleHog Path:  ")
        pathFieldPanel.add(pathLabel)
        self.trufflehogPathField = JTextField(self.trufflehog_exec_path, 40)
        pathFieldPanel.add(self.trufflehogPathField)
        browseButton = JButton("Browse")
        browseButton.addActionListener(lambda event: self.showFileChooser())
        pathFieldPanel.add(browseButton)
        truffleConfigPanel.add(pathFieldPanel)
        configsPanel.add(truffleConfigPanel)

        burpConfigPanel = JPanel()
        burpConfigPanel.setLayout(BoxLayout(burpConfigPanel, BoxLayout.Y_AXIS))
        toolLabel = JEditorPane(
            "text/html",
            "<h3 style='margin-bottom:0; padding-top: 0px'>Burp Configurations</h3>"
            "<p style='font-size:9px; margin-top: 0px; padding-top: 0px'>Choose the Burp traffic to analyze.</p>"
        )
        toolLabel.setEditable(False)
        toolLabel.setOpaque(False)
        burpConfigPanel.add(toolLabel)

        toolPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.toolCheckboxes = {}
        for tool in self.TOOL_ORDER:
            name = self.TOOL_FLAGS[tool]['name']
            active = self.TOOL_FLAGS[tool]['active']
            checkbox = JCheckBox(name, active)
            checkbox.addItemListener(ToolCheckboxListener(self, tool))
            self.toolCheckboxes[tool] = checkbox
            toolPanel.add(checkbox)
        burpConfigPanel.add(toolPanel)
        configsPanel.add(burpConfigPanel)

        topPanel.add(configsPanel)
        return topPanel

    def showFileChooser(self):
        chooser = JFileChooser()
        chooser.setDialogTitle("Select TruffleHog Binary")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        ret = chooser.showOpenDialog(self.panel)
        if ret == JFileChooser.APPROVE_OPTION:
            selected_file = chooser.getSelectedFile()
            selected_path = selected_file.getAbsolutePath()
            if selected_path != self.trufflehog_exec_path:
                self.trufflehog_exec_path = selected_path
                self.trufflehogPathField.setText(selected_path)
                self._callbacks.saveExtensionSetting(self.SETTING_TRUFFLEHOG_PATH, selected_path)
                self.reloadTruffleHog()

    def initSecretTable(self):
        renderer = SecretCellRenderer(self)
        for col in range(self.secretTable.getColumnCount()):
            if col == 2:
                column = self.secretTable.getColumnModel().getColumn(col)
                column.setMinWidth(0)
                column.setMaxWidth(0)
                column.setWidth(0)
            self.secretTable.getColumnModel().getColumn(col).setCellRenderer(renderer)
        self.secretTable.setAutoCreateRowSorter(True)
        self.secretTable.addMouseListener(SecretSelectionListener(self))

    def getTabCaption(self):
        base_title = "TruffleHog"
        unread = len(self.unread_secrets)
        if unread > 0:
            base_title = base_title + " (" + str(unread) + ")"
        return base_title

    def updateTabCaption(self):
        if self.tabbedPane is not None:
            new_title = self.getTabCaption()
            SwingUtilities.invokeLater(lambda: self._setBurpTabTitle(new_title))

    def _setBurpTabTitle(self, new_title):
        count = self.tabbedPane.getTabCount()
        for i in range(count):
            if self.tabbedPane.getComponentAt(i) == self.panel:
                self.tabbedPane.setTitleAt(i, new_title)
                break

    def getUiComponent(self):
        return self.panel

    def refreshSecretTable(self):
        self.secretModel.fireTableDataChanged()
        self.secretTable.repaint()

    def addSecret(self, secret_type, secret_raw, secret_redacted, url, messageInfo, advisory, existing_secret=False):
        self.secrets_data[secret_raw] = {"type": secret_type, "urls": [(url, messageInfo, advisory)]}
        self.secretModel.addRow([secret_type, secret_redacted, secret_raw])
        if not existing_secret:
            self.unread_secrets.add(secret_raw)
        self.refreshSecretTable()
        self.updateTabCaption()
        self.highlightTabTemporarily(3)

    def highlightTabTemporarily(self, duration=3):
        self.tabbedPane.setBackgroundAt(self.tabIndex, Color(int("0xff6633", 16)))
        def revert():
            time.sleep(duration)
            defaultColor = self.tabbedPane.getForegroundAt(self.tabIndex)
            self.tabbedPane.setBackgroundAt(self.tabIndex, defaultColor)
        t = Thread(target=revert)
        t.setDaemon(True)
        t.start()

    def updateSecretUrls(self, secret_raw, url, mi, advisory):
        existing_urls = self.secrets_data[secret_raw]["urls"]
        for (u, _, _) in existing_urls:
            if u == url:
                return
        self.secrets_data[secret_raw]["urls"].append((url, mi, advisory))
        selectedRow = self.secretTable.getSelectedRow()
        if selectedRow != -1:
            actualRow = self.secretTable.convertRowIndexToModel(selectedRow)
            currentSelected = self.secretModel.getValueAt(actualRow, 2)
            if currentSelected == secret_raw:
                self.loadUrlsForSecret(secret_raw)

    def loadUrlsForSecret(self, secret_raw):
        self.urlModel.setRowCount(0)
        for (url, _, _) in self.secrets_data[secret_raw]["urls"]:
            self.urlModel.addRow([url])

    def loadDetailsForUrl(self, secret_raw, url):
        u, mi, adv = None, None, None
        for (_u, _mi, _adv) in self.secrets_data[secret_raw]["urls"]:
            if _u == url:
                u, mi, adv = _u, _mi, _adv
                break

        if u is None:
            self.advisoryPane.setText("<html><body><p>No details available.</p></body></html>")
            self.requestViewer.setMessage(None, True)
            self.responseViewer.setMessage(None, False)
            return

        self.advisoryPane.setText("<html><body>" + (adv if adv else "No details.") + "</body></html>")
        if mi is not None:
            self.requestViewer.setMessage(mi.getRequest(), True)
            resp = mi.getResponse() if mi.getResponse() else b"Secret is located in the request."
            self.responseViewer.setMessage(resp, False)
        else:
            self.requestViewer.setMessage(None, True)
            self.responseViewer.setMessage(None, False)

    def isToolEnabled(self, toolFlag):
        return self.TOOL_FLAGS.get(toolFlag, {}).get('active', False)

    def setExtender(self, extender):
        self.extender = extender

    def getVerifySecretsFlag(self):
        return self.verifySecretsCheckbox.isSelected()

    def getAllowOverlapFlag(self):
        return self.overlappingVerificationCheckbox.isSelected()

    def load_enabled_tools(self):
        for tool, details in self.TOOL_FLAGS.items():
            loaded_setting = self._callbacks.loadExtensionSetting(SETTING_PREFIX + str(tool))
            if loaded_setting == "false":
                details['active'] = False
            elif loaded_setting == "true":
                details['active'] = True
            else:
                self._callbacks.saveExtensionSetting(SETTING_PREFIX + str(tool), "true" if details['active'] else "false")

    def save_enabled_tools(self):
        for tool, details in self.TOOL_FLAGS.items():
            setting_key = SETTING_PREFIX + str(tool)
            setting_value = "true" if details['active'] else "false"
            self._callbacks.saveExtensionSetting(setting_key, setting_value)

    def reloadTruffleHog(self):
        if self.is_reloading:
            return
        self.is_reloading = True
        def perform_reload():
            try:
                if self.extender is not None:
                    self.extender.restart_external_process_background()
            except Exception as e:
                print("Error during reload: " + str(e))
                SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                    self.panel,
                    "Failed to reload TruffleHog with new settings. Error Message: " + str(e),
                    "Error",
                    JOptionPane.ERROR_MESSAGE
                ))
            finally:
                self.is_reloading = False
        Thread(target=perform_reload).start()

    def run_which(self, path):
        if not path:
            return ""
        try:
            if os.path.isabs(path) and os.access(path, os.X_OK):
                return path
            found_path = shutil.which(path)
            if found_path and os.path.isabs(found_path) and os.access(found_path, os.X_OK):
                return found_path
        except Exception as e:
            self._callbacks.printError("Error locating executable: " + str(e))
        return ""

class SecretCellRenderer(DefaultTableCellRenderer):
    def __init__(self, truffle_tab):
        super(SecretCellRenderer, self).__init__()
        self.truffle_tab = truffle_tab

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        component = super(SecretCellRenderer, self).getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        secret_raw = table.getValueAt(row, 2)
        if secret_raw in self.truffle_tab.unread_secrets:
            component.setFont(component.getFont().deriveFont(Font.BOLD))
        else:
            component.setFont(component.getFont().deriveFont(Font.PLAIN))
        return component

class SecretSelectionListener(MouseAdapter):
    def __init__(self, truffle_tab):
        self.truffle_tab = truffle_tab

    def mousePressed(self, event):
        if event.isConsumed():
            return
        table = event.getSource()
        row = table.rowAtPoint(event.getPoint())
        if row >= 0:
            table.setRowSelectionInterval(row, row)
            modelRow = table.convertRowIndexToModel(row)
            secret_raw = table.getModel().getValueAt(modelRow, 2)
            if secret_raw in self.truffle_tab.unread_secrets:
                self.truffle_tab.unread_secrets.remove(secret_raw)
                self.truffle_tab.updateTabCaption()
                SwingUtilities.invokeLater(lambda: table.repaint())
            self.truffle_tab.loadUrlsForSecret(secret_raw)
            SwingUtilities.invokeLater(lambda: self.updateUI())
            event.consume()

    def updateUI(self):
        self.truffle_tab.advisoryPane.setText("<html><body>Select a URL to see details</body></html>")
        self.truffle_tab.requestViewer.setMessage("Select a URL to see details", True)
        self.truffle_tab.responseViewer.setMessage("Select a URL to see details", False)

class URLSelectionListener(MouseAdapter):
    def __init__(self, truffle_tab):
        self.truffle_tab = truffle_tab

    def mousePressed(self, event):
        if event.isConsumed():
            return
        table = event.getSource()
        row = table.rowAtPoint(event.getPoint())
        if row >= 0:
            table.setRowSelectionInterval(row, row)
            selectedSecretRow = self.truffle_tab.secretTable.getSelectedRow()
            if selectedSecretRow == -1:
                return
            secretModelRow = self.truffle_tab.secretTable.convertRowIndexToModel(selectedSecretRow)
            secret_raw = self.truffle_tab.secretModel.getValueAt(secretModelRow, 2)
            urlModelRow = table.convertRowIndexToModel(row)
            url = table.getModel().getValueAt(urlModelRow, 0)
            SwingUtilities.invokeLater(lambda: self.truffle_tab.loadDetailsForUrl(secret_raw, url))
            event.consume()

class LinkOpener(HyperlinkListener):
    def hyperlinkUpdate(self, e):
        if e.getEventType() == HyperlinkEvent.EventType.ACTIVATED:
            if Desktop.isDesktopSupported() and Desktop.getDesktop().isSupported(Desktop.Action.BROWSE):
                Desktop.getDesktop().browse(URI(e.getURL().toExternalForm()))

class CheckboxChangeListener(ItemListener):
    def __init__(self, truffle_tab):
        self.truffle_tab = truffle_tab

    def itemStateChanged(self, event):
        if event.getStateChange() in (ItemEvent.SELECTED, ItemEvent.DESELECTED):
            self.truffle_tab.reloadTruffleHog()

class ToolCheckboxListener(ItemListener):
    def __init__(self, truffle_tab, tool_flag):
        self.truffle_tab = truffle_tab
        self.tool_flag = tool_flag

    def itemStateChanged(self, event):
        self.truffle_tab.TOOL_FLAGS[self.tool_flag]['active'] = (event.getStateChange() == ItemEvent.SELECTED)
        self.truffle_tab.save_enabled_tools()
