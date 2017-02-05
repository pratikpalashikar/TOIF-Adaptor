package com.kdmanalytics.toif.adaptor;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.commons.io.IOUtils;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLReaderFactory;
import java.io.BufferedReader;

import com.kdmanalytics.toif.common.exception.ToifException;
import com.kdmanalytics.toif.framework.files.IFileResolver;
import com.kdmanalytics.toif.framework.toolAdaptor.AbstractAdaptor;
import com.kdmanalytics.toif.framework.toolAdaptor.AdaptorOptions;
import com.kdmanalytics.toif.framework.toolAdaptor.Language;
import com.kdmanalytics.toif.framework.xmlElements.entities.Element;
import com.kdmanalytics.toif.pmd.PmdBugsParser;

/*
 * @author pratik
 * 
 */
public class PmdAdaptor extends AbstractAdaptor {

	String OS = System.getProperty("os.name");
  
  private static final String SECURITYPLUGIN_VERSION = "v1.2.1";
  
  private static final String PMD_VERSION = "3.0.0";
  
  private static final Logger LOG = LoggerFactory.getLogger(PmdAdaptor.class);
 
  /**
   * By default we expect the executable to be in path
   */
  private String execPath = "pmd.bat";
  
  {
    // Override path for linux
    if (isLinux()) {
      execPath = "pmd";
    }
  }
  
  /**
   * the name of the adaptor
   */
  @Override
  public String getAdaptorName() {
    return "Pmd";
  }
  
  /**
   * the description of the adaptor
   */
  @Override
  public String getAdaptorDescription() {
    return "Pmd finds bugs in Java Programs with the added functionality of the security plugin.";
  }
  
  /**
   * the xml produced form the tool is parsed by a sax parser and our own content handler.
   * 
   * @throws ToifException
   */
  @Override
  public ArrayList<Element> parse(java.io.File process, AdaptorOptions options, IFileResolver resolver,
                                  boolean[] validLines, boolean unknownCWE) throws ToifException {
    // InputStream inputStream = null;
    try {
      InputStream fis = null;
      String theString = "";
      try {
        fis = new FileInputStream(process);
        StringWriter writer = new StringWriter();
        IOUtils.copy(fis, writer, "UTF-8");
        theString = writer.toString();
      } finally {
        if (fis != null) fis.close();
      }
      
      // inputStream = new ByteArrayInputStream(theString.getBytes(StandardCharsets.UTF_8));
      // Thread stderr;
      final PmdBugsParser parser = new PmdBugsParser(getProperties(), resolver, getAdaptorName(), unknownCWE);
      
      // final ByteArrayOutputStream errStream = new ByteArrayOutputStream();
      
      /*
       * The two streams could probably be merged with redirectErrorStream(), that was we would only
       * have to deal with one stream.
       */
      
      // stderr = new Thread(new StreamGobbler(inputStream, errStream));
      //
      // stderr.start();
      // stderr.join();
      //
      // final byte[] data = errStream.toByteArray();
      // final ByteArrayInputStream in = new ByteArrayInputStream(data);
      
      final XMLReader rdr = XMLReaderFactory.createXMLReader("org.apache.xerces.parsers.SAXParser");
      rdr.setContentHandler(parser);
      rdr.parse(new InputSource(new StringReader(theString)));
      
      // return the elements gathered during the parse.
      ArrayList<Element> elements = parser.getElements();
      
      return elements;
      
    } catch (final SAXException e) {
      
      final String msg = getAdaptorName()
                         + ": Possibly the file the tool is run against is too large, the wrong kind of file, or not just one file.";
      LOG.error(msg, e);
      e.printStackTrace();
      throw new ToifException(msg);
    } catch (final IOException e) {
      final String msg = getAdaptorName()
                         + ": Possibly the file the tool is run against is too large, the wrong kind of file, or not just one file.";
                         
      LOG.error(msg, e);
      throw new ToifException(msg);
      
    }
    // finally
    // {
    // if(inputStream != null) {
    // try {
    // inputStream.close();
    // }
    // catch (IOException e) {
    // e.printStackTrace();
    // }
    // }
    // }
    // catch (final InterruptedException e) {
    // final String msg = getAdaptorName()
    // + ": Possibly the file the tool is run against is too large, the wrong kind of file, or not
    // just one file.";
    //
    // LOG.error(msg, e);
    // throw new ToifException(msg);
    //
    // }
  }
  
  /**
   * get the commands required to run the tool. Unfortunately findbugs is a bat under windows. This
   * requires that the cmd.exe be called to execute it. This means that we have to determine what
   * system the adaptor is running on.
   */
  @Override
  public String[] runToolCommands(AdaptorOptions options, String[] otherOpts) {
    
    // There is an extra '--' that was added to the args that should
    // be removed (but kept for logging)
    List<String> cleanOpts = new LinkedList<String>();
    for (String opt : otherOpts) {
      if ("--".equals(opt)) continue;
      cleanOpts.add(opt);
    }
    cleanOpts.remove("--");
    otherOpts = cleanOpts.toArray(new String[cleanOpts.size()]);
    
    // if the system is linux, findugs can b eexecuted on its own.
    if (isLinux()) {
      String execPath = this.execPath;
      if (options.getExecutablePath() != null) execPath = options.getExecutablePath().getAbsolutePath();
      
      // the basic command to run the tool.
      final String[] commands = {
                                  execPath, "-xml", options.getInputFile().toString()
      };
      
      // inserting the optional arguments into that array.
      List<String> commandList;
      commandList = new ArrayList<String>();
      commandList.addAll(Arrays.asList(commands));
      commandList.addAll(commands.length - 1, Arrays.asList(otherOpts));
      String[] s = commandList.toArray(new String[commandList.size()]);
      
      // return the commands.
      return s;
    }
    /*
     * if the system is windows then findbugs must be run within the cmd.exe.
     */
    else {
      String execPath = this.execPath;
      if (options.getExecutablePath() != null) execPath = options.getExecutablePath().getAbsolutePath();
      // the basic commands to run the tool
      final String[] commands = {
                                  execPath, "-d",options.getInputFile().toString(),"-f","xml","-rulesets","java-braces,java-clone,java-comments,java-empty,java-finalizers,java-imports,java-j2ee,java-javabeans,java-junit,java-logging-jakarta-commons,java-logging-java,java-naming,java-optimizations,java-strictexception,java-strings,java-sunsecure,java-typeresolution","-encoding","UTF-8","-failOnViolation","false",
      };
      
      // inserting the optional arguments into the commands array.
      List<String> commandList;
      commandList = new ArrayList<String>();
      commandList.addAll(Arrays.asList(commands));
      commandList.addAll(commands.length - 1, Arrays.asList(otherOpts));
      String[] s = commandList.toArray(new String[commandList.size()]);
      
      // return the commands.
      return s;
    }
    
  }
  
  /**
   * testing method
   * 
   * @return
   */
  boolean isLinux() {
    return "Linux".equals(OS);
  }
  
  /**
   * testing method
   * 
   * @param oS
   */
  public void setOS(String oS) {
    OS = oS;
  }
  
  /**
   * get the address of the adaptor's vendor.
   */
  @Override
  public String getAdaptorVendorAddress() {
    return "1956 Robertson Road, Suite 204, Ottawa ON, K2H 5B9";
  }
  
  /**
   * get the description of the adaptor's vendor.
   */
  @Override
  public String getAdaptorVendorDescription() {
    return "KDM Analytics is a security assurance company providing products and services for threat risk assessment and management, due diligence assessments, and information and data assurance. Leveraging our decades of experience in static analysis, reverse engineering and formal methods, we have created breakthrough products for the automated and systematic investigation of code, data and networks.";
  }
  
  /**
   * get the email address of the adaptor's vendor.
   */
  @Override
  public String getAdaptorVendorEmail() {
    return "info@kdmanalytics.com";
  }
  
  /**
   * get the name of the adaptor's vendor.
   */
  @Override
  public String getAdaptorVendorName() {
    return "KDM Analytics";
  }
  
  /**
   * get the phone number of the adaptor's vendor.
   */
  @Override
  public String getAdaptorVendorPhone() {
    return "1-613-627-1010";
  }
  
  /**
   * get the description of the generator
   */
  @Override
  public String getGeneratorDescription() {
    return "Static code analysis tool that analyses Java bytecode and detects a wide range of problems.";
  }
  
  /**
   * get the name of the generator
   */
  @Override
  public String getGeneratorName() {
    return "Pmd";
  }
  
  /**
   * get the address of the vendor.
   */
  @Override
  public String getGeneratorVendorAddress() {
    return "513 summit avenue";
  }
  
  /**
   * get the vendors' description
   */
  @Override
  public String getGeneratorVendorDescription() {
    return "SourceForge is a web-based source code repository.";
  }
  
  /**
   * get email address of vendors email
   */
  @Override
  public String getGeneratorVendorEmail() {
    return "pratikpalashikar@gmail.com";
  }
  
  /**
   * get name of generator's vendor
   */
  @Override
  public String getGeneratorVendorName() {
    return "pratik";
  }
  
  /**
   * get the phone number of the generator's vendor
   */
  @Override
  public String getGeneratorVendorPhone() {
    return "";
  }
  
  /**
   * get the generator's version. This is done by calling the generator with its version options and
   * parsing that output. Again to execute findbugs on windows, it has to be run from within the
   * cmd.exe shell
   */
  @Override
  public String getGeneratorVersion() {
    ProcessBuilder findbugs = null;
    
    // if the system is linux, run normally
    if (isLinux()) {
      String[] commands = {
                            "pmd", "-version"
      };
      findbugs = new ProcessBuilder(commands);
    }
    
    // if the system is windows, run the tool inside cmd.exe
    else {
      String[] commands = {
                            "cmd.exe", "pmd.bat", "-version"
      };
      findbugs = new ProcessBuilder(commands);
    }
    
    // parse the output
    try {
      //InputStream in = startProcess(findbugs);
      
      //BufferedReader br = new BufferedReader(new InputStreamReader(in));
      
      //String strLine;
      /*
      while ((strLine = br.readLine()) != null) {
        if (strLine.trim().equals(PMD_VERSION)) {
          return strLine.trim() + " (+" + SECURITYPLUGIN_VERSION + ")";
        } else {
          // give a warning if the versions do not match.
          System.err.println(getAdaptorName() + ": Generator " + strLine + " found, only version " + PMD_VERSION
                             + " has been tested");
          return strLine.trim();
        }
      
	  }
	  */
      
    } catch (Exception e) {
      System.err.println("Could not run program to gather generator version. " + e);
    }
    
    return "";
  }
  
  /**
   * method used to aid the testing of the getGeneratorVersion method. We need some indirection so
   * that this class can be partially mocked.
   * 
   * @param process
   * @return
   * @throws IOException
   */
  protected InputStream startProcess(ProcessBuilder process) throws IOException {
    Process findbugsInstance = process.start();
    InputStream in = findbugsInstance.getInputStream();
    return in;
  }
  
  @Override
  public String getRuntoolName() {
    return "pmd";
  }
  
  @Override
  public Language getLanguage() {
    return Language.JAVA;
  }
  
  @Override
  public boolean acceptsDOptions() {
    return false;
  }
  
  @Override
  public boolean acceptsIOptions() {
    return false;
  }

}
