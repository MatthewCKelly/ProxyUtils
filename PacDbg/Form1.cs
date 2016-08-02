using Jint;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Permissions;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace PacDbg
{

    public partial class Form1 : Form
    {

        delegate void SetTextCallback(string text);
        private delegate string GetStringParameterDelegate();
        /// <summary>
        /// Runs background task to update proxy
        /// </summary>
        BackgroundWorker worker = new BackgroundWorker();



        /// <summary>
        /// Stores Execution History in a List
        /// </summary>
        List<string> executionHistory = new List<string>();

        /// <summary>
        /// For file loading
        /// </summary>
        // List<string> testURLS = new List<string>();
        List<string> testURLS = new List<string>();

        /// <summary>
        /// Proxy Functions
        /// </summary>
        /// <param name="host"></param>
        /// <param name="pattern"></param>
        /// <returns></returns>
        delegate bool localHostOrDomainIsDelegate(string host, string pattern);
        delegate string myIpAddressDelegate();
        delegate bool isResolvableDelegate(string host);
        delegate bool dateRangeDelegate(string start, string end);
        delegate bool weekdayRangeDelegate(string start, string end);
        delegate bool timeRangeDelegate(int start, int end);
        delegate bool isPlainHostNameDelegate(string host);
        delegate bool dnsDomainIsDelegate(string host, string domain);
        delegate string dnsResolveDelegate(string host);
        delegate void alertDelegate(string message);
        delegate bool IsInNetDelegate(string host, string pattern, string mask);
        delegate int dnsDomainLevelsDelegate(string host);
        delegate bool shExpMatchDelegate(string str, string shexp);

        string lastStatement = string.Empty;
        public Form1()
        {
            InitializeComponent();
        }


        string GetStatus()
        {
            if (InvokeRequired)
            {
                // We're not in the UI thread, so we need to call Invoke
                return (string)Invoke(new GetStringParameterDelegate(GetStatus));
            }

            // Property returns a string
            return textEditor1.Text;
        }

        private int SearchBytePattern(byte[] pattern, byte[] bytes)
        {
            int matches = 0;
            // precomputing this shaves some seconds from the loop execution
            int maxloop = bytes.Length - pattern.Length;
            for (int i = 0; i < maxloop; i++)
            {
                if (pattern[0] == bytes[i])
                {
                    bool ismatch = true;
                    for (int j = 1; j < pattern.Length; j++)
                    {
                        if (bytes[i + j] != pattern[j])
                        {
                            ismatch = false;
                            break;
                        }
                    }
                    if (ismatch)
                    {
                        matches = i;
                        i += pattern.Length - 1;
                    }
                }
            }
            return matches;
        }


        private void GetSystemProxy()
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");

            if (key != null)
            {
                textBoxPacFile.Text = key.GetValue("AutoConfigURL", "").ToString();

                // dodgy method to get PAC file set via auto detect settings
                // this method is not 100% and should be replaced with a proper method
                byte[] bytes = (byte[])key.OpenSubKey("Connections").GetValue("DefaultConnectionSettings", null);

                if (bytes != null)
                {
                    byte[] searchPattern = new byte[4] { 26, 0, 0, 0 };
                    int i = SearchBytePattern(searchPattern, bytes) + 4;

                    string wpad = System.Text.Encoding.ASCII.GetString(bytes, i, bytes.Length - i);
                    wpad = wpad.Substring(0, wpad.IndexOf('\0'));

                    if (string.IsNullOrEmpty(textBoxPacFile.Text))
                    {
                        if (wpad.Contains(":/"))
                        {
                            if (!string.IsNullOrEmpty(wpad))
                            {
                                textBoxPacFile.Text = wpad;
                            }
                        }
                    }
                    else
                    {

                        if (wpad.Length > 4)
                        {
                            if (wpad != textBoxPacFile.Text)
                            {
                                MessageBox.Show(string.Format("WARNING: AutoDetect PAC file is '{0}' and configured proxy PAC is '{1}'",
                                    wpad,
                                    textBoxPacFile.Text),
                                    "PacDbg",
                                    MessageBoxButtons.OK,
                                    MessageBoxIcon.Warning);
                            }
                        }
                    }
                }

            }

            LoadProxy();

        }

        private void Form1_Load(object sender, EventArgs e)
        {
            worker.DoWork += worker_DoWork;
            worker.RunWorkerCompleted += worker_RunWorkerCompleted;
            textBoxURL.Text = "http://www.google.co.nz/";

            GetSystemProxy();

        }

        void worker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            Invoke(new Action(delegate
            {
                toolStripButtonRun.Enabled = true;
            }));
        }

        /// <summary>
        /// Permission required, otherwise Jint DLL throws exeption
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        [PermissionSet(SecurityAction.Assert, Unrestricted = true)]
        void jint_Step(object sender, Jint.Debugger.DebugInformation e)
        {
            if (!e.CurrentStatement.Source.Code.StartsWith("FindProxyForURL"))
            {
                listBox1.Invoke(new Action(delegate
                {
                    listBox1.Items.Add(string.Format("{0}: {1}\n", e.CurrentStatement.Source, e.CurrentStatement.Source.Code));
                    listBox1.SelectedIndex = listBox1.Items.Count - 1;
                    string source = e.CurrentStatement.Source.ToString();
                    if (source.Contains(" "))
                    {
                        string lineNumber = source.Split(' ')[1];
                        int line;
                        if (Int32.TryParse(lineNumber, out line))
                        {
                            textEditor1.SelectAll();
                            textEditor1.SelectionBackColor = textEditor1.BackColor;
                            textEditor1.Select(textEditor1.GetFirstCharIndexFromLine(line - 1), textEditor1.Lines[line - 1].Length);
                            textEditor1.SelectionBackColor = Color.Yellow;
                            //    //    textEditor1.HighlightActiveLine = true;
                            //    //    textEditor1.GotoLine(line - 1);
                        }
                    }


                }));
            }

        }

        /// <summary>
        /// Permission required or Jint throws exception.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        [PermissionSet(SecurityAction.Assert, Unrestricted = true)]
        void worker_DoWork(object sender, DoWorkEventArgs e)
        {


            //  var script = (string)textEditor1.Invoke(new Func<string>(() => textEditor1.Text));
            string script = GetStatus();

            // string script = textEditor1.Text.ToString();
            IsInNetDelegate IsInNet = PacExtensions.IsInNetAction;
            localHostOrDomainIsDelegate localHostOrDomainIs = PacExtensions.localHostOrDomainIs;
            myIpAddressDelegate myIpAddress = PacExtensions.myIpAddress;
            isResolvableDelegate isResolvable = PacExtensions.isResolvable;
            dateRangeDelegate dateRange = PacExtensions.dateRange;
            weekdayRangeDelegate weekdayRange = PacExtensions.weekdayRange;
            timeRangeDelegate timeRange = PacExtensions.timeRange;
            isPlainHostNameDelegate isPlainHostName = PacExtensions.isPlainHostName;
            dnsDomainIsDelegate dnsDomainIs = PacExtensions.dnsDomainIs;
            dnsResolveDelegate dnsResolve = PacExtensions.dnsResolve;
            alertDelegate alert = PacExtensions.alert;
            dnsDomainLevelsDelegate dnsDomainLevels = PacExtensions.dnsDomainLevels;
            shExpMatchDelegate shExpMatch = PacExtensions.shExpMatch;

            JintEngine jint = new JintEngine()
                .SetDebugMode(true)
                .SetFunction("isInNet", IsInNet)
                .SetFunction("localHostOrDomainIs", localHostOrDomainIs)
                .SetFunction("myIpAddress", myIpAddress)
                .SetFunction("isResolvable", isResolvable)
                .SetFunction("dateRange", dateRange)
                .SetFunction("weekdayRange", weekdayRange)
                .SetFunction("timeRange", timeRange)
                .SetFunction("isPlainHostName", isPlainHostName)
                .SetFunction("dnsDomainIs", dnsDomainIs)
                .SetFunction("dnsResolve", dnsResolve)
                .SetFunction("alert", alert)
                .SetFunction("dnsDomainLevels", dnsDomainLevels)
                .SetFunction("shExpMatch", shExpMatch);

            try
            {
                jint.Step += jint_Step;
                // Not sure why replacing text ??
                // textEditor1.Text = script;

                var result = jint.Run(script);

                executionHistory.Clear();
                listBox1.Invoke(new Action(delegate
                {
                    listBox1.Items.Clear();
                }));

                Uri uri;
                
                //if (!textBoxURL.Text.Contains("://"))
                //{
                //    Invoke(new Action(delegate
                //        {
                //            textBoxURL.Text = "http://" + textBoxURL.Text;
                //        }));
                //}


                if (testURLS.Count > 0) {
                    // have url list..
                } else {
                    testURLS.Add(textBoxURL.Text);

                }

                foreach (string strUrl in testURLS) {
                    
                    if (!Uri.TryCreate(strUrl, UriKind.Absolute, out uri))
                    {
                        listView1.Invoke(new Action(delegate
                        {
                            listView1.Items.Add(string.Format("'{0}' is not a valid URL", textBoxURL.Text), 2);
                        }));
                    }
                    else
                    {
                        PacExtensions.CounterReset();
                        result = jint.Run(string.Format("FindProxyForURL(\"{0}\",\"{1}\")", uri.ToString(), uri.Host));

                        Trace.WriteLine(result);
                        listProxyResults1.Invoke(new Action(delegate
                        {
                            listView1.Items.Add(string.Format("Testing URL: {0}", strUrl),0 );
                            listView1.Items.Add(string.Format("IsInNet Count: {0} Total Duration: {1} ms", PacExtensions.IsInNetCount, PacExtensions.IsInNetDuration.Milliseconds), 0);
                            listView1.Items.Add(string.Format("DnsDomainIs Count: {0} Total Duration: {1} ms", PacExtensions.DnsDomainIsCount, PacExtensions.DnsDomainIsDuration.Milliseconds), 0);

                            string[] arr = new string[4];
                            ListViewItem itm;
                            //add items to ListView
                            arr[0] = listProxyResults1.Items.Count.ToString();
                            arr[1] = strUrl;
                            arr[2] = result.ToString();
                            arr[3] = DateTime.Now.ToString("yyyyMMddHHmmssfff");

                            // arr[2] = ((line - 1).ToString() + " : " + textEditor1.Lines[line - 1]);
                            itm = new ListViewItem(arr);
                            listProxyResults1.Items.Add(itm);
                            listProxyResults1.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
                            listProxyResults1.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
                            foreach (string s in PacExtensions.EvaluationHistory)
                            {
                                listView1.Items.Add(s, 0);
                            }
                        }));
                    }


                } // end of foreach url...


            }

            catch (Jint.Native.JsException ex)
            {
                listBox1.Invoke(new Action(delegate
                {
                    string msg = ex.Message.Replace("An unexpected error occurred while parsing the script. Jint.JintException: ", "");
                    listView1.Items.Add(msg, 2);
                }));


            }
            catch (System.NullReferenceException)
            {
                listBox1.Invoke(new Action(delegate
                {
                    string msg = "Null reference. Probably variable/function not defined, remember functions and variables are case sensitive.";
                    listView1.Items.Add(msg, 2);
                }));
            }
            catch (JintException ex)
            {
                listBox1.Invoke(new Action(delegate
                {
                    int i = ex.InnerException.ToString().IndexOf(":");

                    string msg = ex.InnerException.ToString();

                    if (msg.Contains("line"))
                    {
                        int x = msg.IndexOf("line");
                        int y = msg.IndexOf(":", x);
                        if (y > 0)
                        {
                        string lineNumber = msg.Substring(x + 5, y - x - 5);
                        int line;
                        if (Int32.TryParse(lineNumber, out line))
                            {

                            textEditor1.SelectAll();
                            textEditor1.SelectionBackColor = textEditor1.BackColor;
                            textEditor1.Select(textEditor1.GetFirstCharIndexFromLine(line - 1), textEditor1.Lines[line - 1].Length);
                            textEditor1.SelectionBackColor = Color.Yellow;
                            //        textEditor1.HighlightActiveLine = true;
                            //        textEditor1.GotoLine(line - 1);
                            }
                        }
                    }

                    if (i > 0)
                    {
                        msg = msg.Substring(i + 1);
                    }
                    msg = msg.Substring(0, msg.IndexOf("  at Jint."));

                    if (msg.Contains("Object reference not set to an instance of an object."))
                    {
                        msg = "Variable/Function not defined. Remember variables/functions are case sensitive.";
                    }

                    //.Replace("An unexpected error occurred while parsing the script. Jint.JintException: ", "");
                    listView1.Items.Add(msg, 2);

                    if (!msg.Contains("Variable/Function not defined."))
                    {

                        listBox1.Items.Add(string.Format("Fatal Error: {0}. {1}", ex.Message, ex.InnerException));
                    }
                }));
            }
            catch (Exception ex)
            {
                listBox1.Invoke(new Action(delegate
                {
                    listBox1.Items.Add(string.Format("Fatal Error: {0}", ex.Message));
                }));
            }
        }

        /// <summary>
        /// Loads Proxy....
        /// </summary>
        private void LoadProxy()
        {
            string filename = textBoxPacFile.Text;

            try
            {
                if (textBoxPacFile.Text.Contains("://"))
                {

                    using (WebClient Client = new WebClient())
                    {
                        filename = Path.GetTempFileName();
                        Client.DownloadFile(textBoxPacFile.Text, filename);
                        using (StreamReader sr = new StreamReader(filename))
                        {
                            textEditor1.Text = sr.ReadToEnd().ToString().Replace('\t', ' ');
                        }
                    }
                }

                listView1.Items.Clear();

                if (textBoxPacFile.Text.StartsWith("file:"))
                {
                    listView1.Items.Add(
                        "Proxy PAC is set via file:// not all applications support this method, please use http location", 1);
                }

                if (!string.IsNullOrEmpty(filename))
                {
                    using (StreamReader reader = href.Utils.EncodingTools.OpenTextFile(filename))
                    {
                        if (reader.CurrentEncoding.GetType() != typeof(System.Text.ASCIIEncoding))
                        {
                            listView1.Items.Add(string.Format("PAC file is {0} encoded. Some applications may only support ASCII encoded PAC files", reader.CurrentEncoding.EncodingName), 1);
                        }
                        else
                        {
                            listView1.Items.Add("PAC file is ASCII encoded", 0);
                        }

                        textEditor1.Text = reader.ReadToEnd().ToString().Replace('\t', ' ');
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(string.Format("Unable to open '{0}' Error: {1}", textBoxPacFile.Text,
                    ex.Message),
                    "PacDbg",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }
        private void textEditor1_Click(object sender, EventArgs e)
        {

        }

        private void Form1_Resize(object sender, EventArgs e)
        {
            textEditor1.Width = Width - textEditor1.Left - 20;
            textEditor1.Height = Height - textEditor1.Top - 50;
        }

        private void toolStripButtonRun_Click(object sender, EventArgs e)
        {

            toolStripButtonRun.Enabled = false;
            listView1.Items.Clear();
            /*
            this.demoThread =new Thread(new ThreadStart(worker.RunWorkerAsync));

            this.demoThread.Start();
            */

            //
            worker.RunWorkerAsync();
        }

        private void listBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (listBox1.SelectedIndex >= 0)
            {
                string source = listBox1.SelectedItem.ToString();
                if (source.Contains(" "))
                {
                    string lineNumber = source.Split(' ')[1];
                    int line;
                    if (Int32.TryParse(lineNumber, out line))
                   {
                        System.Diagnostics.Debug.WriteLine  ((line - 1).ToString() + " : " + textEditor1.Lines[line - 1]);
                        textEditor1.SelectAll();
                        textEditor1.SelectionBackColor = textEditor1.BackColor;
                        textEditor1.Select(textEditor1.GetFirstCharIndexFromLine(line - 1), textEditor1.Lines[line - 1].Length);
                        textEditor1.SelectionBackColor = Color.Yellow;
                        //    //    textEditor1.HighlightActiveLine = true;
                        //    //    textEditor1.GotoLine(line - 1);
                    }
                }
            }
        }

        private void toolStripButtonOpenSystemPac_Click(object sender, EventArgs e)
        {
            GetSystemProxy();
        }

        private void toolStripButtonOpenPacFile_Click(object sender, EventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.Filter = "PAC Files (*.pac; wpad.dat)|*.pac;wpad.dat|All Files (*.*)|*.*";
            if (dialog.ShowDialog() == DialogResult.OK)
            {
                textBoxPacFile.Text = dialog.FileName;
                LoadProxy();
            }
        }

        private void toolStripButtonOpenTestFile_Click(object sender, EventArgs e)
        {
            // Open a text file that contains 1 url per line.
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*";
            if (dialog.ShowDialog() == DialogResult.OK)
            {
                textBoxURL.Text = dialog.FileName;
                toolStripLabel1.Text = "Test URL Text File";
                textBoxURL.BackColor = System.Drawing.Color.LightPink;
                textBoxURL.ToolTipText = "List of URL's to test with,\r\nEach line will be tested against the loaded PAC file.";

                // load file and read each line into testURLS
                int counter = 1;
                string line;
                testURLS.Clear();
                try {
                    // Read the file and display it line by line.
                    System.IO.StreamReader file = new System.IO.StreamReader(dialog.FileName);
                    while ((line = file.ReadLine()) != null)
                    {
                        line = line.Trim();
                        if (line.Length > 3)   
                        {

                            // dont add comments to file
                            if (line.Substring(0, 1) != "#")
                            {
                                testURLS.Add(line);
                                listView1.Items.Add(string.Format("Line: {0} - URL {1}: {2}", counter, testURLS.Count, line));

                            }
                            else {
                                // line not added to list
                            }

                        }
                        else {
                            // still want line numbers..
                           
                        }

                        counter++;
                    }

                    file.Close();




                    
                }

                catch (Exception ex)
                {
                    MessageBox.Show(string.Format("Unable read input file. Error '{0}'",
                        ex.Message),
                        "PacDbg",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                }
                //LoadProxy();
            }
        }

        private void textBoxURL_DblClick(object sender, EventArgs e)
        {
            toolStripButtonOpenTestFile_Click(sender, e);
        }

        private void toolStripButtonSaveToDisk_Click(object sender, EventArgs e)
        {
            try
            {
                SaveFileDialog dialog = new SaveFileDialog();
                dialog.Filter = "PAC Files (*.pac; wpad.dat)|*.pac;wpad.dat|All Files (*.*)|*.*";
                if (dialog.ShowDialog() == DialogResult.OK)
                {
                    using (StreamWriter sw = new StreamWriter(dialog.FileName, false, Encoding.ASCII))
                    {
                        sw.Write(textEditor1.Text);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(string.Format("Unable to save. Error '{0}'",
                    ex.Message),
                    "PacDbg",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        private void toolStrip1_ItemClicked(object sender, ToolStripItemClickedEventArgs e)
        {

        }

        private void listProxyResults1_SelectedIndexChanged(object sender, EventArgs e)
        {

        }


    }
}
